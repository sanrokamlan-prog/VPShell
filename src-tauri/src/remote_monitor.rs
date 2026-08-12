use std::{
    collections::{HashMap, VecDeque},
    io::{Read, Write},
    path::Path,
    process::{Command, ExitStatus, Stdio},
    sync::{Arc, Mutex, MutexGuard},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};

use crate::configure_process_ssh_askpass;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(12);
const STDOUT_LIMIT: usize = 192 * 1024;
const STDERR_LIMIT: usize = 64 * 1024;
const BEGIN_MARKER: &str = "__VPSHELL_METRICS_V1_BEGIN__";
const END_MARKER: &str = "__VPSHELL_METRICS_V1_END__";
const MONITOR_EVENT: &str = "remote-monitor-update";
const MIN_INTERVAL_SECONDS: u64 = 5;
const MAX_INTERVAL_SECONDS: u64 = 300;
const MAX_MONITOR_SESSIONS: usize = 16;
const MAX_MONITOR_WORKERS: usize = 16;
const MAX_HISTORY_POINTS: usize = 120;
const INITIAL_SAMPLE_DELAY: Duration = Duration::from_secs(5);
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(100);

// This script is static: no host, username, path, or other local input is
// interpolated into it. It intentionally targets Linux hosts with /proc.
const REMOTE_METRICS_SCRIPT: &str = r#"#!/bin/sh
LC_ALL=C
export LC_ALL

printf '%s\n' '__VPSHELL_METRICS_V1_BEGIN__'
if [ ! -r /proc/stat ] || [ ! -r /proc/meminfo ] || [ ! -r /proc/net/dev ]; then
  printf '%s\n' 'ERROR	linux_proc_required'
  printf '%s\n' '__VPSHELL_METRICS_V1_END__'
  exit 41
fi

host_name=$(hostname 2>/dev/null | tr '\t\r\n' '   ' | cut -c 1-255)
primary_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -z "$primary_ip" ] && command -v ip >/dev/null 2>&1; then
  primary_ip=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") {print $(i + 1); exit}}')
fi
printf 'HOSTNAME\t%s\n' "$host_name"
printf 'PRIMARY_IP\t%s\n' "$primary_ip"

cpu_a=$(awk 'NR == 1 {print; exit}' /proc/stat)
net_a=$(awk -F '[: ]+' 'NR > 2 && $2 != "lo" {rx += $3; tx += $11} END {printf "%.0f %.0f", rx, tx}' /proc/net/dev)
tick_a=$(awk '{print $1; exit}' /proc/uptime)
sleep 1
cpu_b=$(awk 'NR == 1 {print; exit}' /proc/stat)
net_b=$(awk -F '[: ]+' 'NR > 2 && $2 != "lo" {rx += $3; tx += $11} END {printf "%.0f %.0f", rx, tx}' /proc/net/dev)
tick_b=$(awk '{print $1; exit}' /proc/uptime)

cpu_percent=$(awk -v first="$cpu_a" -v second="$cpu_b" 'BEGIN {
  n1 = split(first, a, /[[:space:]]+/); n2 = split(second, b, /[[:space:]]+/);
  total1 = 0; total2 = 0;
  for (i = 2; i <= n1 && i <= 9; i++) total1 += a[i];
  for (i = 2; i <= n2 && i <= 9; i++) total2 += b[i];
  idle1 = a[5] + a[6]; idle2 = b[5] + b[6];
  delta = total2 - total1; busy = delta - (idle2 - idle1);
  if (delta <= 0) printf "0.00"; else {
    value = busy * 100 / delta;
    if (value < 0) value = 0; if (value > 100) value = 100;
    printf "%.2f", value;
  }
}')
printf 'CPU\t%s\n' "$cpu_percent"

awk '
  $1 == "MemTotal:" {total = $2}
  $1 == "MemAvailable:" {available = $2}
  $1 == "MemFree:" {free = $2}
  $1 == "Buffers:" {buffers = $2}
  $1 == "Cached:" {cached = $2}
  END {
    if (available <= 0) available = free + buffers + cached;
    used = total - available; if (used < 0) used = 0;
    percent = total > 0 ? used * 100 / total : 0;
    printf "MEMORY\t%.2f\t%.0f\t%.0f\n", percent, used * 1024, total * 1024;
  }
' /proc/meminfo

df -Pk / 2>/dev/null | awk 'NR == 2 {
  percent = $5; gsub(/%/, "", percent);
  printf "DISK\t%.2f\t%.0f\t%.0f\n", percent + 0, $3 * 1024, $2 * 1024;
}'
awk '{printf "LOAD\t%s\t%s\t%s\n", $1, $2, $3; exit}' /proc/loadavg
awk '{printf "UPTIME\t%.0f\n", $1; exit}' /proc/uptime

awk -v first="$net_a" -v second="$net_b" -v start="$tick_a" -v finish="$tick_b" 'BEGIN {
  split(first, a, " "); split(second, b, " "); elapsed = finish - start;
  if (elapsed <= 0) elapsed = 1;
  rx = (b[1] - a[1]) / elapsed; tx = (b[2] - a[2]) / elapsed;
  if (rx < 0) rx = 0; if (tx < 0) tx = 0;
  printf "NETWORK\t%.0f\t%.0f\t%.0f\n", rx, tx, elapsed * 1000;
}'

if command -v ps >/dev/null 2>&1; then
  ps -eo pid=,pcpu=,pmem=,comm= --sort=-pcpu 2>/dev/null | awk 'NR <= 5 {
    pid = $1; cpu = $2; mem = $3; $1 = ""; $2 = ""; $3 = "";
    sub(/^[[:space:]]+/, "", $0); gsub(/[\t\r\n]/, " ", $0);
    printf "PROCESS\t%s\t%s\t%s\t%s\n", pid, cpu, mem, substr($0, 1, 128);
  }'
fi
printf '%s\n' '__VPSHELL_METRICS_V1_END__'
"#;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorRequest {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub identity_file: Option<String>,
    pub credential_ref: Option<String>,
    pub identity_passphrase_ref: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProcessMetric {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f64,
    pub memory_percent: f64,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RemoteMetrics {
    pub connection_host: String,
    pub hostname: String,
    pub primary_ip: Option<String>,
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub disk_percent: f64,
    pub disk_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub load_one: f64,
    pub load_five: f64,
    pub load_fifteen: f64,
    pub uptime_seconds: u64,
    pub rx_bytes_per_second: u64,
    pub tx_bytes_per_second: u64,
    pub sample_window_ms: u64,
    pub top_processes: Vec<ProcessMetric>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartMonitorRequest {
    pub session_id: String,
    pub interval_seconds: u64,
    pub connection: MonitorRequest,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MonitorTrendPoint {
    pub sampled_at_ms: u64,
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub disk_percent: f64,
    pub load_one: f64,
    pub rx_bytes_per_second: u64,
    pub tx_bytes_per_second: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MonitorSnapshot {
    pub session_id: String,
    pub interval_seconds: u64,
    pub paused: bool,
    pub sampling: bool,
    pub latest: Option<RemoteMetrics>,
    pub history: Vec<MonitorTrendPoint>,
    pub last_error: Option<String>,
    pub total_samples: u64,
    pub dropped_samples: u64,
}

struct MonitorRecord {
    request: MonitorRequest,
    generation: u64,
    interval_seconds: u64,
    paused: bool,
    sampling: bool,
    latest: Option<RemoteMetrics>,
    history: VecDeque<MonitorTrendPoint>,
    last_error: Option<String>,
    total_samples: u64,
    dropped_samples: u64,
}

#[derive(Default)]
struct MonitorRegistry {
    next_generation: u64,
    workers: usize,
    sessions: HashMap<String, MonitorRecord>,
}

#[derive(Clone, Default)]
pub(crate) struct RemoteMonitorManager {
    inner: Arc<Mutex<MonitorRegistry>>,
}

struct BoundedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

#[derive(Default)]
struct ParsedMetrics {
    hostname: Option<String>,
    primary_ip: Option<String>,
    cpu_percent: Option<f64>,
    memory: Option<(f64, u64, u64)>,
    disk: Option<(f64, u64, u64)>,
    load: Option<(f64, f64, f64)>,
    uptime_seconds: Option<u64>,
    network: Option<(u64, u64, u64)>,
    top_processes: Vec<ProcessMetric>,
}

fn validate_session_id(session_id: &str) -> Result<(), String> {
    if session_id.is_empty()
        || session_id.len() > 128
        || !session_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err("监控会话标识格式无效".to_string());
    }
    Ok(())
}

fn validate_interval(interval_seconds: u64) -> Result<(), String> {
    if !(MIN_INTERVAL_SECONDS..=MAX_INTERVAL_SECONDS).contains(&interval_seconds) {
        return Err(format!(
            "监控频率必须在 {MIN_INTERVAL_SECONDS} 到 {MAX_INTERVAL_SECONDS} 秒之间"
        ));
    }
    Ok(())
}

fn sampled_at_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn trend_point(metrics: &RemoteMetrics, sampled_at_ms: u64) -> MonitorTrendPoint {
    MonitorTrendPoint {
        sampled_at_ms,
        cpu_percent: metrics.cpu_percent,
        memory_percent: metrics.memory_percent,
        disk_percent: metrics.disk_percent,
        load_one: metrics.load_one,
        rx_bytes_per_second: metrics.rx_bytes_per_second,
        tx_bytes_per_second: metrics.tx_bytes_per_second,
    }
}

fn snapshot(session_id: &str, record: &MonitorRecord) -> MonitorSnapshot {
    MonitorSnapshot {
        session_id: session_id.to_string(),
        interval_seconds: record.interval_seconds,
        paused: record.paused,
        sampling: record.sampling,
        latest: record.latest.clone(),
        history: record.history.iter().cloned().collect(),
        last_error: record.last_error.clone(),
        total_samples: record.total_samples,
        dropped_samples: record.dropped_samples,
    }
}

impl RemoteMonitorManager {
    fn lock(&self) -> Result<MutexGuard<'_, MonitorRegistry>, String> {
        self.inner
            .lock()
            .map_err(|_| "主机监控状态已损坏".to_string())
    }

    fn start(&self, request: StartMonitorRequest) -> Result<(u64, MonitorSnapshot), String> {
        validate_session_id(&request.session_id)?;
        validate_interval(request.interval_seconds)?;
        validate_request(&request.connection)?;

        let mut registry = self.lock()?;
        if !registry.sessions.contains_key(&request.session_id)
            && registry.sessions.len() >= MAX_MONITOR_SESSIONS
        {
            return Err(format!("同时监控的会话不能超过 {MAX_MONITOR_SESSIONS} 个"));
        }
        if registry.workers >= MAX_MONITOR_WORKERS {
            return Err(format!(
                "监控工作线程已达到 {MAX_MONITOR_WORKERS} 个上限，请等待正在停止的采样结束"
            ));
        }

        registry.next_generation = registry.next_generation.wrapping_add(1).max(1);
        let generation = registry.next_generation;
        registry.workers += 1;
        let session_id = request.session_id;
        let record = MonitorRecord {
            request: request.connection,
            generation,
            interval_seconds: request.interval_seconds,
            paused: false,
            sampling: false,
            latest: None,
            history: VecDeque::with_capacity(MAX_HISTORY_POINTS),
            last_error: None,
            total_samples: 0,
            dropped_samples: 0,
        };
        let result = snapshot(&session_id, &record);
        registry.sessions.insert(session_id, record);
        Ok((generation, result))
    }

    fn get(&self, session_id: &str) -> Result<MonitorSnapshot, String> {
        validate_session_id(session_id)?;
        let registry = self.lock()?;
        registry
            .sessions
            .get(session_id)
            .map(|record| snapshot(session_id, record))
            .ok_or_else(|| "监控会话不存在或已停止".to_string())
    }

    fn stop(&self, session_id: &str) -> Result<(), String> {
        validate_session_id(session_id)?;
        self.lock()?.sessions.remove(session_id);
        Ok(())
    }

    fn set_paused(&self, session_id: &str, paused: bool) -> Result<MonitorSnapshot, String> {
        validate_session_id(session_id)?;
        let mut registry = self.lock()?;
        let record = registry
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| "监控会话不存在或已停止".to_string())?;
        record.paused = paused;
        Ok(snapshot(session_id, record))
    }

    fn set_interval(
        &self,
        session_id: &str,
        interval_seconds: u64,
    ) -> Result<MonitorSnapshot, String> {
        validate_session_id(session_id)?;
        validate_interval(interval_seconds)?;
        let mut registry = self.lock()?;
        let record = registry
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| "监控会话不存在或已停止".to_string())?;
        record.interval_seconds = interval_seconds;
        Ok(snapshot(session_id, record))
    }

    fn is_current(&self, session_id: &str, generation: u64) -> bool {
        self.lock()
            .ok()
            .and_then(|registry| {
                registry
                    .sessions
                    .get(session_id)
                    .map(|record| record.generation == generation)
            })
            .unwrap_or(false)
    }

    fn paused_and_interval(&self, session_id: &str, generation: u64) -> Option<(bool, u64)> {
        self.lock().ok().and_then(|registry| {
            registry.sessions.get(session_id).and_then(|record| {
                (record.generation == generation)
                    .then_some((record.paused, record.interval_seconds))
            })
        })
    }

    fn begin_sample(
        &self,
        session_id: &str,
        generation: u64,
    ) -> Option<(MonitorRequest, MonitorSnapshot)> {
        let mut registry = self.lock().ok()?;
        let record = registry.sessions.get_mut(session_id)?;
        if record.generation != generation || record.paused || record.sampling {
            return None;
        }
        record.sampling = true;
        Some((record.request.clone(), snapshot(session_id, record)))
    }

    fn complete_sample(
        &self,
        session_id: &str,
        generation: u64,
        result: Result<RemoteMetrics, String>,
        timestamp_ms: u64,
    ) -> Option<MonitorSnapshot> {
        let mut registry = self.lock().ok()?;
        let record = registry.sessions.get_mut(session_id)?;
        if record.generation != generation || !record.sampling {
            return None;
        }
        record.sampling = false;
        if record.paused {
            return Some(snapshot(session_id, record));
        }

        match result {
            Ok(metrics) => {
                if record.history.len() == MAX_HISTORY_POINTS {
                    record.history.pop_front();
                    record.dropped_samples = record.dropped_samples.saturating_add(1);
                }
                record
                    .history
                    .push_back(trend_point(&metrics, timestamp_ms));
                record.latest = Some(metrics);
                record.last_error = None;
                record.total_samples = record.total_samples.saturating_add(1);
            }
            Err(error) => {
                record.last_error = Some(error);
            }
        }
        Some(snapshot(session_id, record))
    }

    fn worker_finished(&self) {
        if let Ok(mut registry) = self.lock() {
            registry.workers = registry.workers.saturating_sub(1);
        }
    }
}

fn validate_request(request: &MonitorRequest) -> Result<(), String> {
    let host = request.host.as_str();
    if host.is_empty() || host.len() > 255 || host.starts_with('-') {
        return Err("主机地址格式无效".to_string());
    }
    if !host.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || matches!(character, '.' | '-' | '_' | ':' | '[' | ']' | '%')
    }) {
        return Err("主机地址包含不安全字符".to_string());
    }
    if request.port == 0 {
        return Err("SSH 端口必须在 1 到 65535 之间".to_string());
    }

    let username = request.username.as_str();
    if username.is_empty()
        || username.len() > 128
        || username.starts_with('-')
        || username.contains('@')
        || !username.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '+')
        })
    {
        return Err("SSH 用户名格式无效".to_string());
    }

    if let Some(identity_file) = request
        .identity_file
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        if identity_file.len() > 4096
            || identity_file.chars().any(char::is_control)
            || !Path::new(identity_file).is_file()
        {
            return Err("SSH 私钥文件不存在或路径无效".to_string());
        }
    }
    Ok(())
}

fn read_bounded<R: Read>(mut reader: R, limit: usize) -> BoundedOutput {
    let mut bytes = Vec::with_capacity(limit.min(16 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    let mut truncated = false;
    loop {
        let length = match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(length) => length,
        };
        let remaining = limit.saturating_sub(bytes.len());
        let retained = remaining.min(length);
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained < length;
    }
    BoundedOutput { bytes, truncated }
}

fn should_terminate(elapsed: Duration, timeout: Duration) -> bool {
    elapsed >= timeout
}

fn parse_number<T>(value: Option<&str>, label: &str) -> Result<T, String>
where
    T: std::str::FromStr,
{
    value
        .ok_or_else(|| format!("主机概况缺少 {label}"))?
        .parse::<T>()
        .map_err(|_| format!("主机概况中的 {label} 数值无效"))
}

fn parse_percent(value: Option<&str>, label: &str) -> Result<f64, String> {
    let value = parse_number::<f64>(value, label)?;
    if !value.is_finite() || !(0.0..=100.0).contains(&value) {
        return Err(format!("主机概况中的 {label} 超出范围"));
    }
    Ok(value)
}

fn parse_metrics(output: &str, connection_host: String) -> Result<RemoteMetrics, String> {
    let begin = output
        .find(BEGIN_MARKER)
        .ok_or_else(|| "远端未返回可识别的主机概况数据".to_string())?;
    let body_start = begin + BEGIN_MARKER.len();
    let relative_end = output[body_start..]
        .find(END_MARKER)
        .ok_or_else(|| "远端主机概况数据不完整".to_string())?;
    let body = &output[body_start..body_start + relative_end];
    let mut parsed = ParsedMetrics::default();

    for raw_line in body.lines() {
        let line = raw_line.trim_end_matches('\r').trim_start_matches('\n');
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split('\t');
        match fields.next().unwrap_or_default() {
            "ERROR" => {
                return Err(match fields.next() {
                    Some("linux_proc_required") => {
                        "主机概况目前仅支持可读取 /proc 的 Linux 主机".to_string()
                    }
                    _ => "远端无法采集主机概况".to_string(),
                });
            }
            "HOSTNAME" => {
                parsed.hostname = Some(fields.next().unwrap_or_default().to_string());
            }
            "PRIMARY_IP" => {
                parsed.primary_ip = fields
                    .next()
                    .filter(|value| !value.is_empty())
                    .map(str::to_string);
            }
            "CPU" => parsed.cpu_percent = Some(parse_percent(fields.next(), "CPU 使用率")?),
            "MEMORY" => {
                parsed.memory = Some((
                    parse_percent(fields.next(), "内存使用率")?,
                    parse_number(fields.next(), "已用内存")?,
                    parse_number(fields.next(), "总内存")?,
                ));
            }
            "DISK" => {
                parsed.disk = Some((
                    parse_percent(fields.next(), "磁盘使用率")?,
                    parse_number(fields.next(), "已用磁盘")?,
                    parse_number(fields.next(), "总磁盘")?,
                ));
            }
            "LOAD" => {
                let one = parse_number::<f64>(fields.next(), "1 分钟负载")?;
                let five = parse_number::<f64>(fields.next(), "5 分钟负载")?;
                let fifteen = parse_number::<f64>(fields.next(), "15 分钟负载")?;
                if [one, five, fifteen]
                    .iter()
                    .any(|value| !value.is_finite() || *value < 0.0)
                {
                    return Err("主机概况中的负载数值无效".to_string());
                }
                parsed.load = Some((one, five, fifteen));
            }
            "UPTIME" => {
                parsed.uptime_seconds = Some(parse_number(fields.next(), "运行时间")?);
            }
            "NETWORK" => {
                parsed.network = Some((
                    parse_number(fields.next(), "下载速率")?,
                    parse_number(fields.next(), "上传速率")?,
                    parse_number(fields.next(), "采样时间")?,
                ));
            }
            "PROCESS" if parsed.top_processes.len() < 5 => {
                let pid = parse_number(fields.next(), "进程 PID")?;
                let cpu_percent = parse_number::<f64>(fields.next(), "进程 CPU")?;
                let memory_percent = parse_number::<f64>(fields.next(), "进程内存")?;
                let name = fields.next().unwrap_or_default().trim().to_string();
                if name.len() > 128
                    || !cpu_percent.is_finite()
                    || cpu_percent < 0.0
                    || !memory_percent.is_finite()
                    || memory_percent < 0.0
                {
                    return Err("主机概况中的进程数据无效".to_string());
                }
                parsed.top_processes.push(ProcessMetric {
                    pid,
                    name,
                    cpu_percent,
                    memory_percent,
                });
            }
            _ => {}
        }
    }

    let (memory_percent, memory_used_bytes, memory_total_bytes) = parsed
        .memory
        .ok_or_else(|| "主机概况缺少内存数据".to_string())?;
    let (disk_percent, disk_used_bytes, disk_total_bytes) = parsed
        .disk
        .ok_or_else(|| "主机概况缺少磁盘数据".to_string())?;
    let (load_one, load_five, load_fifteen) = parsed
        .load
        .ok_or_else(|| "主机概况缺少负载数据".to_string())?;
    let (rx_bytes_per_second, tx_bytes_per_second, sample_window_ms) = parsed
        .network
        .ok_or_else(|| "主机概况缺少网络数据".to_string())?;

    Ok(RemoteMetrics {
        connection_host,
        hostname: parsed.hostname.unwrap_or_default(),
        primary_ip: parsed.primary_ip,
        cpu_percent: parsed
            .cpu_percent
            .ok_or_else(|| "主机概况缺少 CPU 数据".to_string())?,
        memory_percent,
        memory_used_bytes,
        memory_total_bytes,
        disk_percent,
        disk_used_bytes,
        disk_total_bytes,
        load_one,
        load_five,
        load_fifteen,
        uptime_seconds: parsed
            .uptime_seconds
            .ok_or_else(|| "主机概况缺少运行时间".to_string())?,
        rx_bytes_per_second,
        tx_bytes_per_second,
        sample_window_ms,
        top_processes: parsed.top_processes,
    })
}

fn sanitize_error(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .take(600)
        .collect::<String>()
        .trim()
        .to_string()
}

fn ssh_failure(status: ExitStatus, stderr: &[u8]) -> String {
    let detail = sanitize_error(stderr);
    let lower = detail.to_ascii_lowercase();
    if lower.contains("permission denied") {
        return "服务器拒绝了这次主机概况认证；已保存凭据未被删除，也不能仅凭独立采样失败判定导入密码错误".to_string();
    }
    if lower.contains("no supported authentication")
        || lower.contains("no more authentication methods")
    {
        return "服务器不接受主机概况采样使用的认证方式；当前终端会话可能仍然正常".to_string();
    }
    if lower.contains("host key verification failed")
        || lower.contains("no host key is known")
        || lower.contains("remote host identification has changed")
    {
        return "SSH 主机密钥校验失败：请先核对并将主机指纹加入系统 known_hosts".to_string();
    }
    if lower.contains("connection timed out") || lower.contains("operation timed out") {
        return "连接主机超时，请检查地址、端口或网络".to_string();
    }
    if lower.contains("could not resolve hostname") || lower.contains("name or service not known") {
        return "无法解析主机地址".to_string();
    }
    if lower.contains("connection refused") {
        return "SSH 连接被拒绝，请检查端口和服务状态".to_string();
    }
    if lower.contains("too many authentication failures") {
        return "服务器因认证尝试过多拒绝了独立采样连接；已保存凭据未被判为错误，稍后会自动重试"
            .to_string();
    }
    if detail.is_empty() {
        format!(
            "独立的 SSH 主机概况连接失败（退出状态 {status}，远端未返回详情）；当前终端与凭据可能仍然正常，稍后自动重试"
        )
    } else {
        format!("SSH 主机概况采集失败: {detail}")
    }
}

fn fetch_remote_metrics_blocking(request: MonitorRequest) -> Result<RemoteMetrics, String> {
    validate_request(&request)?;

    let use_askpass = request.credential_ref.is_some() || request.identity_passphrase_ref.is_some();

    let mut command = Command::new("ssh");
    command
        .arg("-T")
        .arg("-o")
        .arg(if use_askpass {
            "BatchMode=no"
        } else {
            "BatchMode=yes"
        })
        .arg("-o")
        .arg("ConnectTimeout=8")
        .arg("-o")
        .arg("ConnectionAttempts=1")
        .arg("-o")
        .arg("ServerAliveInterval=5")
        .arg("-o")
        .arg("ServerAliveCountMax=1")
        .arg("-o")
        .arg("StrictHostKeyChecking=yes")
        .arg("-o")
        .arg(format!(
            "KexAlgorithms={}",
            crate::file_transfer::openssh_kex_algorithms()?
        ))
        .arg("-o")
        .arg("LogLevel=ERROR")
        .arg("-p")
        .arg(request.port.to_string());

    if use_askpass {
        configure_process_ssh_askpass(
            &mut command,
            request.credential_ref.as_deref(),
            request.identity_passphrase_ref.as_deref(),
        )?;
    } else {
        command
            .arg("-o")
            .arg("NumberOfPasswordPrompts=0")
            .arg("-o")
            .arg("PasswordAuthentication=no")
            .arg("-o")
            .arg("KbdInteractiveAuthentication=no")
            .env("SSH_ASKPASS_REQUIRE", "never");
    }

    let identity_file = request
        .identity_file
        .as_deref()
        .filter(|value| !value.is_empty());
    if let Some(identity_file) = identity_file {
        command
            .arg("-o")
            .arg("IdentitiesOnly=yes")
            .arg("-i")
            .arg(identity_file);
    }
    if request.credential_ref.is_some() {
        command
            .arg("-o")
            .arg("IdentitiesOnly=yes")
            .arg("-o")
            .arg(if identity_file.is_some() {
                "PreferredAuthentications=publickey,keyboard-interactive,password"
            } else {
                "PreferredAuthentications=keyboard-interactive,password"
            })
            .arg("-o")
            .arg("PasswordAuthentication=yes")
            .arg("-o")
            .arg("KbdInteractiveAuthentication=yes");
    }

    command
        .arg("--")
        .arg(format!("{}@{}", request.username, request.host))
        .arg("sh")
        .arg("-s")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    hide_console_window(&mut command);

    let mut child = command
        .spawn()
        .map_err(|error| format!("无法启动系统 OpenSSH，请确认 ssh 已安装: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "无法读取 OpenSSH 标准输出".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "无法读取 OpenSSH 错误输出".to_string())?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout, STDOUT_LIMIT));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, STDERR_LIMIT));

    if let Some(mut stdin) = child.stdin.take() {
        if let Err(error) = stdin.write_all(REMOTE_METRICS_SCRIPT.as_bytes()) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(format!("无法向远端发送主机概况采集命令: {error}"));
        }
    }

    let started = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (Some(status), false),
            Ok(None) if should_terminate(started.elapsed(), PROCESS_TIMEOUT) => {
                let _ = child.kill();
                let status = child.wait().ok();
                break (status, true);
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(format!("无法等待 OpenSSH 主机概况任务: {error}"));
            }
        }
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| "读取 OpenSSH 标准输出的线程异常结束".to_string())?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "读取 OpenSSH 错误输出的线程异常结束".to_string())?;
    if timed_out {
        return Err("主机概况采集超过 12 秒，任务已终止".to_string());
    }
    if stdout.truncated || stderr.truncated {
        return Err("主机概况输出超过 256 KiB 安全上限，已停止解析".to_string());
    }

    let output = String::from_utf8_lossy(&stdout.bytes);
    if output.contains("ERROR\tlinux_proc_required") {
        return Err("主机概况目前仅支持可读取 /proc 的 Linux 主机".to_string());
    }
    let status = status.ok_or_else(|| "无法取得 OpenSSH 退出状态".to_string())?;
    if !status.success() {
        return Err(ssh_failure(status, &stderr.bytes));
    }
    parse_metrics(&output, request.host)
}

#[cfg(target_os = "windows")]
fn hide_console_window(command: &mut Command) {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(target_os = "windows"))]
fn hide_console_window(_command: &mut Command) {}

fn emit_snapshot(app: &AppHandle, snapshot: &MonitorSnapshot) {
    let _ = app.emit(MONITOR_EVENT, snapshot.clone());
}

fn wait_until_due(
    manager: &RemoteMonitorManager,
    session_id: &str,
    generation: u64,
    initial: bool,
) -> bool {
    let mut elapsed = Duration::ZERO;
    loop {
        let Some((paused, interval_seconds)) = manager.paused_and_interval(session_id, generation)
        else {
            return false;
        };
        if paused {
            thread::sleep(WORKER_POLL_INTERVAL);
            continue;
        }
        let target = if initial {
            INITIAL_SAMPLE_DELAY
        } else {
            Duration::from_secs(interval_seconds)
        };
        if elapsed >= target {
            return true;
        }
        let sleep_for = WORKER_POLL_INTERVAL.min(target.saturating_sub(elapsed));
        thread::sleep(sleep_for);
        elapsed = elapsed.saturating_add(sleep_for);
    }
}

fn monitor_worker(
    app: AppHandle,
    manager: RemoteMonitorManager,
    session_id: String,
    generation: u64,
) {
    let mut initial = true;
    while wait_until_due(&manager, &session_id, generation, initial) {
        initial = false;
        let Some((request, sampling_snapshot)) = manager.begin_sample(&session_id, generation)
        else {
            if !manager.is_current(&session_id, generation) {
                break;
            }
            continue;
        };
        emit_snapshot(&app, &sampling_snapshot);
        let result = fetch_remote_metrics_blocking(request);
        let Some(completed_snapshot) =
            manager.complete_sample(&session_id, generation, result, sampled_at_ms())
        else {
            break;
        };
        emit_snapshot(&app, &completed_snapshot);
    }
    manager.worker_finished();
}

#[tauri::command]
pub fn start_remote_monitor(
    app: AppHandle,
    manager: State<'_, RemoteMonitorManager>,
    request: StartMonitorRequest,
) -> Result<MonitorSnapshot, String> {
    let session_id = request.session_id.clone();
    let (generation, initial_snapshot) = manager.start(request)?;
    let worker_manager = manager.inner().clone();
    thread::Builder::new()
        .name(format!("vpshell-monitor-{generation}"))
        .spawn(move || monitor_worker(app, worker_manager, session_id, generation))
        .map_err(|error| {
            let _ = manager.stop(&initial_snapshot.session_id);
            manager.worker_finished();
            format!("无法启动主机监控任务: {error}")
        })?;
    Ok(initial_snapshot)
}

#[tauri::command]
pub fn get_remote_monitor_snapshot(
    manager: State<'_, RemoteMonitorManager>,
    session_id: String,
) -> Result<MonitorSnapshot, String> {
    manager.get(&session_id)
}

#[tauri::command]
pub fn set_remote_monitor_paused(
    app: AppHandle,
    manager: State<'_, RemoteMonitorManager>,
    session_id: String,
    paused: bool,
) -> Result<MonitorSnapshot, String> {
    let result = manager.set_paused(&session_id, paused)?;
    emit_snapshot(&app, &result);
    Ok(result)
}

#[tauri::command]
pub fn set_remote_monitor_interval(
    app: AppHandle,
    manager: State<'_, RemoteMonitorManager>,
    session_id: String,
    interval_seconds: u64,
) -> Result<MonitorSnapshot, String> {
    let result = manager.set_interval(&session_id, interval_seconds)?;
    emit_snapshot(&app, &result);
    Ok(result)
}

#[tauri::command]
pub fn stop_remote_monitor(
    manager: State<'_, RemoteMonitorManager>,
    session_id: String,
) -> Result<(), String> {
    manager.stop(&session_id)
}

#[tauri::command]
pub async fn fetch_remote_metrics(request: MonitorRequest) -> Result<RemoteMetrics, String> {
    tauri::async_runtime::spawn_blocking(move || fetch_remote_metrics_blocking(request))
        .await
        .map_err(|error| format!("主机概况采集任务异常结束: {error}"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> MonitorRequest {
        MonitorRequest {
            host: "203.0.113.10".to_string(),
            port: 22,
            username: "ops".to_string(),
            identity_file: None,
            credential_ref: None,
            identity_passphrase_ref: None,
        }
    }

    fn start_request(session_id: &str, interval_seconds: u64) -> StartMonitorRequest {
        StartMonitorRequest {
            session_id: session_id.to_string(),
            interval_seconds,
            connection: request(),
        }
    }

    fn metrics(cpu_percent: f64) -> RemoteMetrics {
        RemoteMetrics {
            connection_host: "203.0.113.10".to_string(),
            hostname: "test-host".to_string(),
            primary_ip: Some("203.0.113.10".to_string()),
            cpu_percent,
            memory_percent: 40.0,
            memory_used_bytes: 400,
            memory_total_bytes: 1000,
            disk_percent: 50.0,
            disk_used_bytes: 500,
            disk_total_bytes: 1000,
            load_one: 0.5,
            load_five: 0.4,
            load_fifteen: 0.3,
            uptime_seconds: 100,
            rx_bytes_per_second: 1200,
            tx_bytes_per_second: 600,
            sample_window_ms: 1000,
            top_processes: Vec::new(),
        }
    }

    #[test]
    fn validates_hosts_users_and_jump_routes() {
        assert!(validate_request(&request()).is_ok());

        let mut invalid_host = request();
        invalid_host.host = "-oProxyCommand=bad".to_string();
        assert!(validate_request(&invalid_host).is_err());

        let mut invalid_user = request();
        invalid_user.username = "root@other".to_string();
        assert!(validate_request(&invalid_user).is_err());
    }

    #[test]
    fn parses_only_the_marked_metrics_block() {
        let output = format!(
            "banner that must be ignored\n{BEGIN_MARKER}\n\
             HOSTNAME\tweb-01\n\
             PRIMARY_IP\t10.0.0.4\n\
             CPU\t17.25\n\
             MEMORY\t48.50\t1048576\t2097152\n\
             DISK\t61.00\t4096\t8192\n\
             LOAD\t0.10\t0.20\t0.30\n\
             UPTIME\t86400\n\
             NETWORK\t1200\t3400\t1000\n\
             PROCESS\t42\t12.5\t1.5\tnginx\n\
             {END_MARKER}\ntrailing text"
        );
        let metrics = parse_metrics(&output, "203.0.113.10".to_string()).unwrap();
        assert_eq!(metrics.connection_host, "203.0.113.10");
        assert_eq!(metrics.hostname, "web-01");
        assert_eq!(metrics.primary_ip.as_deref(), Some("10.0.0.4"));
        assert_eq!(metrics.cpu_percent, 17.25);
        assert_eq!(metrics.rx_bytes_per_second, 1200);
        assert_eq!(metrics.top_processes[0].name, "nginx");
    }

    #[test]
    fn rejects_missing_markers_and_out_of_range_values() {
        assert!(parse_metrics("CPU\t20", "host".to_string()).is_err());
        let output = format!(
            "{BEGIN_MARKER}\nCPU\t120\nMEMORY\t10\t1\t2\nDISK\t10\t1\t2\n\
             LOAD\t0\t0\t0\nUPTIME\t1\nNETWORK\t0\t0\t1000\n{END_MARKER}"
        );
        assert!(parse_metrics(&output, "host".to_string()).is_err());
    }

    #[test]
    fn timeout_policy_stops_at_the_deadline() {
        assert!(!should_terminate(
            Duration::from_millis(11_999),
            PROCESS_TIMEOUT
        ));
        assert!(should_terminate(PROCESS_TIMEOUT, PROCESS_TIMEOUT));
        assert!(should_terminate(
            Duration::from_millis(12_001),
            PROCESS_TIMEOUT
        ));
    }

    #[test]
    fn bounded_reader_discards_excess_without_growing() {
        let output = read_bounded(&b"abcdefgh"[..], 4);
        assert_eq!(output.bytes, b"abcd");
        assert!(output.truncated);
    }

    #[test]
    fn validates_monitor_identity_frequency_and_worker_limits() {
        assert!(validate_session_id("session_01-a").is_ok());
        assert!(validate_session_id("../session").is_err());
        assert!(validate_session_id("").is_err());
        assert!(validate_interval(MIN_INTERVAL_SECONDS).is_ok());
        assert!(validate_interval(MAX_INTERVAL_SECONDS).is_ok());
        assert!(validate_interval(MIN_INTERVAL_SECONDS - 1).is_err());
        assert!(validate_interval(MAX_INTERVAL_SECONDS + 1).is_err());

        let manager = RemoteMonitorManager::default();
        for index in 0..MAX_MONITOR_WORKERS {
            manager
                .start(start_request(&format!("session-{index}"), 15))
                .unwrap();
        }
        assert!(manager.start(start_request("one-too-many", 15)).is_err());
    }

    #[test]
    fn history_is_bounded_and_reports_retention() {
        let manager = RemoteMonitorManager::default();
        let (generation, _) = manager.start(start_request("history", 15)).unwrap();

        for index in 0..(MAX_HISTORY_POINTS + 5) {
            assert!(manager.begin_sample("history", generation).is_some());
            let snapshot = manager
                .complete_sample(
                    "history",
                    generation,
                    Ok(metrics(index as f64 % 100.0)),
                    index as u64,
                )
                .unwrap();
            assert_eq!(snapshot.total_samples, index as u64 + 1);
        }

        let snapshot = manager.get("history").unwrap();
        assert_eq!(snapshot.history.len(), MAX_HISTORY_POINTS);
        assert_eq!(snapshot.dropped_samples, 5);
        assert_eq!(snapshot.history.first().unwrap().sampled_at_ms, 5);
        assert_eq!(
            snapshot.history.last().unwrap().sampled_at_ms,
            (MAX_HISTORY_POINTS + 4) as u64
        );
    }

    #[test]
    fn pause_discards_in_flight_result_and_resume_is_explicit() {
        let manager = RemoteMonitorManager::default();
        let (generation, _) = manager.start(start_request("pause", 15)).unwrap();
        assert!(manager.begin_sample("pause", generation).is_some());

        let paused = manager.set_paused("pause", true).unwrap();
        assert!(paused.paused);
        assert!(paused.sampling);
        let completed = manager
            .complete_sample("pause", generation, Ok(metrics(20.0)), 1)
            .unwrap();
        assert!(completed.paused);
        assert!(!completed.sampling);
        assert!(completed.history.is_empty());
        assert!(completed.latest.is_none());

        let resumed = manager.set_paused("pause", false).unwrap();
        assert!(!resumed.paused);
        assert!(manager.begin_sample("pause", generation).is_some());
        let completed = manager
            .complete_sample("pause", generation, Ok(metrics(30.0)), 2)
            .unwrap();
        assert_eq!(completed.history.len(), 1);
        assert_eq!(completed.latest.unwrap().cpu_percent, 30.0);
    }

    #[test]
    fn stale_and_stopped_workers_cannot_finalize_samples() {
        let manager = RemoteMonitorManager::default();
        let (old_generation, _) = manager.start(start_request("replace", 15)).unwrap();
        assert!(manager.begin_sample("replace", old_generation).is_some());

        let (new_generation, _) = manager.start(start_request("replace", 30)).unwrap();
        assert_ne!(old_generation, new_generation);
        assert!(
            manager
                .complete_sample("replace", old_generation, Ok(metrics(10.0)), 1)
                .is_none()
        );
        assert_eq!(manager.get("replace").unwrap().interval_seconds, 30);

        assert!(manager.begin_sample("replace", new_generation).is_some());
        manager.stop("replace").unwrap();
        assert!(
            manager
                .complete_sample("replace", new_generation, Ok(metrics(20.0)), 2)
                .is_none()
        );
        assert!(manager.get("replace").is_err());
    }

    #[test]
    fn interval_and_failure_transitions_are_explainable() {
        let manager = RemoteMonitorManager::default();
        let (generation, _) = manager.start(start_request("states", 15)).unwrap();
        assert_eq!(
            manager.set_interval("states", 60).unwrap().interval_seconds,
            60
        );
        assert!(manager.set_interval("states", 1).is_err());

        assert!(manager.begin_sample("states", generation).is_some());
        let failed = manager
            .complete_sample(
                "states",
                generation,
                Err("连接主机超时，请检查地址、端口或网络".to_string()),
                1,
            )
            .unwrap();
        assert_eq!(failed.total_samples, 0);
        assert_eq!(
            failed.last_error.as_deref(),
            Some("连接主机超时，请检查地址、端口或网络")
        );
        assert!(failed.history.is_empty());
    }
}

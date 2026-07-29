use std::{
    io::{Read, Write},
    path::Path,
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

const PROCESS_TIMEOUT: Duration = Duration::from_secs(12);
const STDOUT_LIMIT: usize = 192 * 1024;
const STDERR_LIMIT: usize = 64 * 1024;
const BEGIN_MARKER: &str = "__VPSHELL_METRICS_V1_BEGIN__";
const END_MARKER: &str = "__VPSHELL_METRICS_V1_END__";

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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorRequest {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub proxy_jump: Option<String>,
    pub identity_file: Option<String>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProcessMetric {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f64,
    pub memory_percent: f64,
}

#[derive(Debug, Serialize, PartialEq)]
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

    if let Some(proxy_jump) = request
        .proxy_jump
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        validate_proxy_jump(proxy_jump)?;
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
                Some(
                    suffix
                        .strip_prefix(':')
                        .ok_or_else(|| format!("ProxyJump IPv6 端口格式无效: {hop}"))?,
                )
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
    if lower.contains("permission denied")
        || lower.contains("no supported authentication")
        || lower.contains("publickey")
    {
        return "SSH 身份验证失败：主机概况采用无交互模式，不会识别或自动填写密码提示；请配置私钥或 ssh-agent".to_string();
    }
    if lower.contains("host key verification failed")
        || lower.contains("no host key is known")
        || lower.contains("remote host identification has changed")
    {
        return "SSH 主机密钥校验失败：请先核对并将主机指纹加入系统 known_hosts".to_string();
    }
    if lower.contains("connection timed out") || lower.contains("operation timed out") {
        return "连接主机超时，请检查地址、端口、网络或跳板机".to_string();
    }
    if lower.contains("could not resolve hostname") || lower.contains("name or service not known") {
        return "无法解析主机地址或跳板机地址".to_string();
    }
    if lower.contains("connection refused") {
        return "SSH 连接被拒绝，请检查端口和服务状态".to_string();
    }
    if detail.is_empty() {
        format!("SSH 主机概况采集失败（退出状态 {status}）")
    } else {
        format!("SSH 主机概况采集失败: {detail}")
    }
}

fn fetch_remote_metrics_blocking(request: MonitorRequest) -> Result<RemoteMetrics, String> {
    validate_request(&request)?;

    let mut command = Command::new("ssh");
    command
        .arg("-T")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("NumberOfPasswordPrompts=0")
        .arg("-o")
        .arg("PasswordAuthentication=no")
        .arg("-o")
        .arg("KbdInteractiveAuthentication=no")
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
        .arg("LogLevel=ERROR")
        .arg("-p")
        .arg(request.port.to_string());

    if let Some(proxy_jump) = request
        .proxy_jump
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        command.arg("-J").arg(proxy_jump);
    }
    if let Some(identity_file) = request
        .identity_file
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        command
            .arg("-o")
            .arg("IdentitiesOnly=yes")
            .arg("-i")
            .arg(identity_file);
    }

    command
        .arg("--")
        .arg(format!("{}@{}", request.username, request.host))
        .arg("sh")
        .arg("-s")
        .env("SSH_ASKPASS_REQUIRE", "never")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

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
            proxy_jump: None,
            identity_file: None,
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

        let mut invalid_jump = request();
        invalid_jump.proxy_jump = Some("gateway:0".to_string());
        assert!(validate_request(&invalid_jump).is_err());
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
}

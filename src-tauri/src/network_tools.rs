use std::{
    io::Read,
    net::IpAddr,
    process::Command,
    time::{Duration, Instant},
};

use reqwest::{
    Url,
    blocking::Client,
    header::{ACCEPT_ENCODING, HeaderValue},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};

const MAX_HOST_LENGTH: usize = 253;
const MAX_TRACE_HOPS: u8 = 64;
const MAX_TIMEOUT_SECS: u64 = 300;
const MAX_DOWNLOAD_MB: u64 = 1_024;
const MAX_UDP_DURATION_SECS: u64 = 60;
const MAX_UDP_BANDWIDTH_MBPS: u64 = 10_000;
const BYTES_PER_MB: u64 = 1024 * 1024;
const READ_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceRouteRequest {
    pub host: String,
    pub max_hops: u8,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceRouteResult {
    pub host: String,
    pub max_hops: u8,
    pub command: String,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadSpeedRequest {
    pub url: String,
    pub timeout_secs: u64,
    pub max_download_mb: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadSpeedResult {
    pub status: u16,
    pub bytes_downloaded: u64,
    pub max_bytes: u64,
    pub duration_ms: u64,
    pub megabits_per_second: f64,
    pub content_length: Option<u64>,
    pub reached_limit: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdpSpeedRequest {
    pub host: String,
    pub port: u32,
    pub duration_secs: u64,
    pub bandwidth_mbps: u64,
    pub reverse: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UdpSpeedResult {
    pub host: String,
    pub port: u16,
    pub command: String,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub stdout: String,
    pub stderr: String,
}

/// Runs the platform traceroute command without invoking a shell.
#[tauri::command]
pub async fn trace_route(request: TraceRouteRequest) -> Result<TraceRouteResult, String> {
    let request = validate_trace_request(request)?;

    tauri::async_runtime::spawn_blocking(move || run_trace_route(request))
        .await
        .map_err(|error| format!("路由追踪任务异常终止: {error}"))?
}

/// Downloads at most the requested number of bytes and reports average throughput.
#[tauri::command]
pub async fn download_speed_test(
    request: DownloadSpeedRequest,
) -> Result<DownloadSpeedResult, String> {
    let request = validate_speed_request(request)?;

    tauri::async_runtime::spawn_blocking(move || run_download_speed_test(request))
        .await
        .map_err(|error| format!("下载测速任务异常终止: {error}"))?
}

/// Runs an iperf3 UDP client test. It never installs iperf3 or starts a server.
#[tauri::command]
pub async fn udp_speed_test(request: UdpSpeedRequest) -> Result<UdpSpeedResult, String> {
    let request = validate_udp_speed_request(request)?;

    tauri::async_runtime::spawn_blocking(move || run_udp_speed_test(request))
        .await
        .map_err(|error| format!("UDP 测速任务异常终止: {error}"))?
}

fn validate_trace_request(mut request: TraceRouteRequest) -> Result<TraceRouteRequest, String> {
    request.host = normalize_host(&request.host)?;
    if !(1..=MAX_TRACE_HOPS).contains(&request.max_hops) {
        return Err(format!("最大跳数必须在 1 到 {MAX_TRACE_HOPS} 之间"));
    }
    Ok(request)
}

fn normalize_host(input: &str) -> Result<String, String> {
    let host = input.trim();
    if host.is_empty() {
        return Err("主机地址不能为空".to_string());
    }
    if host.len() > MAX_HOST_LENGTH {
        return Err("主机地址过长".to_string());
    }
    if host.starts_with('-')
        || host.chars().any(|character| {
            character.is_whitespace() || character.is_control() || !character.is_ascii()
        })
    {
        return Err("主机地址格式无效".to_string());
    }

    if host.parse::<IpAddr>().is_ok() {
        return Ok(host.to_string());
    }

    let hostname = host.strip_suffix('.').unwrap_or(host);
    if hostname.is_empty()
        || hostname.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err("主机地址格式无效".to_string());
    }

    Ok(host.to_string())
}

fn validate_speed_request(
    request: DownloadSpeedRequest,
) -> Result<ValidatedDownloadSpeedRequest, String> {
    if !(1..=MAX_TIMEOUT_SECS).contains(&request.timeout_secs) {
        return Err(format!("超时时间必须在 1 到 {MAX_TIMEOUT_SECS} 秒之间"));
    }
    if !(1..=MAX_DOWNLOAD_MB).contains(&request.max_download_mb) {
        return Err(format!("最大下载量必须在 1 到 {MAX_DOWNLOAD_MB} MB 之间"));
    }

    let url = Url::parse(request.url.trim()).map_err(|_| "测速 URL 格式无效".to_string())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("测速 URL 仅支持 http 或 https".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("测速 URL 不允许包含用户名或密码".to_string());
    }
    if url.host_str().is_none() {
        return Err("测速 URL 缺少主机地址".to_string());
    }

    let max_bytes = request
        .max_download_mb
        .checked_mul(BYTES_PER_MB)
        .ok_or_else(|| "最大下载量超出允许范围".to_string())?;

    Ok(ValidatedDownloadSpeedRequest {
        url,
        timeout: Duration::from_secs(request.timeout_secs),
        max_bytes,
    })
}

fn validate_udp_speed_request(mut request: UdpSpeedRequest) -> Result<UdpSpeedRequest, String> {
    request.host = normalize_host(&request.host)?;
    if !(1..=u16::MAX as u32).contains(&request.port) {
        return Err("iperf3 端口必须在 1 到 65535 之间".to_string());
    }
    if !(1..=MAX_UDP_DURATION_SECS).contains(&request.duration_secs) {
        return Err(format!(
            "UDP 测速时长必须在 1 到 {MAX_UDP_DURATION_SECS} 秒之间"
        ));
    }
    if !(1..=MAX_UDP_BANDWIDTH_MBPS).contains(&request.bandwidth_mbps) {
        return Err(format!(
            "UDP 目标带宽必须在 1 到 {MAX_UDP_BANDWIDTH_MBPS} Mbps 之间"
        ));
    }
    Ok(request)
}

struct ValidatedDownloadSpeedRequest {
    url: Url,
    timeout: Duration,
    max_bytes: u64,
}

fn run_trace_route(request: TraceRouteRequest) -> Result<TraceRouteResult, String> {
    let (program, args) = trace_command(&request.host, request.max_hops);
    let display_command = format!("{} {}", program, args.join(" "));
    let mut command = Command::new(program);
    command.args(&args);
    hide_console_window(&mut command);

    let started = Instant::now();
    let output = command
        .output()
        .map_err(|error| format!("无法启动 {program}: {error}。请确认系统已安装路由追踪工具"))?;

    Ok(TraceRouteResult {
        host: request.host,
        max_hops: request.max_hops,
        command: display_command,
        success: output.status.success(),
        exit_code: output.status.code(),
        duration_ms: elapsed_millis(started.elapsed()),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

#[cfg(target_os = "windows")]
fn trace_command(host: &str, max_hops: u8) -> (&'static str, Vec<String>) {
    (
        "tracert",
        vec![
            "-d".to_string(),
            "-h".to_string(),
            max_hops.to_string(),
            "-w".to_string(),
            "3000".to_string(),
            host.to_string(),
        ],
    )
}

#[cfg(not(target_os = "windows"))]
fn trace_command(host: &str, max_hops: u8) -> (&'static str, Vec<String>) {
    (
        "traceroute",
        vec![
            "-n".to_string(),
            "-m".to_string(),
            max_hops.to_string(),
            "-w".to_string(),
            "3".to_string(),
            host.to_string(),
        ],
    )
}

#[cfg(target_os = "windows")]
fn hide_console_window(command: &mut Command) {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(target_os = "windows"))]
fn hide_console_window(_command: &mut Command) {}

fn run_download_speed_test(
    request: ValidatedDownloadSpeedRequest,
) -> Result<DownloadSpeedResult, String> {
    let connect_timeout = request.timeout.min(Duration::from_secs(15));
    let client = Client::builder()
        .timeout(request.timeout)
        .connect_timeout(connect_timeout)
        .redirect(Policy::limited(5))
        .user_agent("VPShell/0.1 network-speed-test")
        .build()
        .map_err(|error| format!("无法初始化测速客户端: {}", error.without_url()))?;

    let started = Instant::now();
    let mut response = client
        .get(request.url)
        .header(ACCEPT_ENCODING, HeaderValue::from_static("identity"))
        .send()
        .map_err(|error| format!("测速请求失败: {}", error.without_url()))?;

    let status = response.status().as_u16();
    let content_length = response.content_length();
    let mut bytes_downloaded = 0_u64;
    let mut buffer = [0_u8; READ_BUFFER_SIZE];

    while bytes_downloaded < request.max_bytes {
        let remaining = request.max_bytes - bytes_downloaded;
        let read_limit = usize::try_from(remaining.min(READ_BUFFER_SIZE as u64))
            .expect("read limit always fits usize");
        let read = response
            .read(&mut buffer[..read_limit])
            .map_err(|error| format!("读取测速数据失败: {error}"))?;
        if read == 0 {
            break;
        }
        bytes_downloaded += read as u64;
    }

    let elapsed = started.elapsed();
    let seconds = elapsed.as_secs_f64().max(f64::EPSILON);
    let megabits_per_second = (bytes_downloaded as f64 * 8.0) / seconds / 1_000_000.0;

    Ok(DownloadSpeedResult {
        status,
        bytes_downloaded,
        max_bytes: request.max_bytes,
        duration_ms: elapsed_millis(elapsed),
        megabits_per_second,
        content_length,
        reached_limit: bytes_downloaded == request.max_bytes,
    })
}

fn run_udp_speed_test(request: UdpSpeedRequest) -> Result<UdpSpeedResult, String> {
    let mut args = vec![
        "-c".to_string(),
        request.host.clone(),
        "-p".to_string(),
        request.port.to_string(),
        "-u".to_string(),
        "-t".to_string(),
        request.duration_secs.to_string(),
        "-b".to_string(),
        format!("{}M", request.bandwidth_mbps),
        "--json".to_string(),
    ];
    if request.reverse {
        args.push("-R".to_string());
    }

    let display_command = format!("iperf3 {}", args.join(" "));
    let mut command = Command::new("iperf3");
    command.args(&args);
    hide_console_window(&mut command);

    let started = Instant::now();
    let output = command.output().map_err(|error| {
        format!("无法启动 iperf3: {error}。请先在本机和目标 VPS 安装 iperf3，并在 VPS 启动服务端")
    })?;

    Ok(UdpSpeedResult {
        host: request.host,
        port: request.port as u16,
        command: display_command,
        success: output.status.success(),
        exit_code: output.status.code(),
        duration_ms: elapsed_millis(started.elapsed()),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn elapsed_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace_request(host: &str, max_hops: u8) -> TraceRouteRequest {
        TraceRouteRequest {
            host: host.to_string(),
            max_hops,
        }
    }

    fn speed_request(url: &str, timeout_secs: u64, max_download_mb: u64) -> DownloadSpeedRequest {
        DownloadSpeedRequest {
            url: url.to_string(),
            timeout_secs,
            max_download_mb,
        }
    }

    fn udp_request(
        host: &str,
        port: u32,
        duration_secs: u64,
        bandwidth_mbps: u64,
    ) -> UdpSpeedRequest {
        UdpSpeedRequest {
            host: host.to_string(),
            port,
            duration_secs,
            bandwidth_mbps,
            reverse: false,
        }
    }

    #[test]
    fn accepts_ipv4_ipv6_and_dns_hosts() {
        for host in [
            "192.0.2.1",
            "2001:db8::1",
            "vps-01.example.com",
            "localhost",
        ] {
            let result = validate_trace_request(trace_request(host, 30));
            assert!(result.is_ok(), "expected {host} to be accepted");
        }
    }

    #[test]
    fn rejects_command_like_or_invalid_hosts() {
        for host in [
            "",
            "-h",
            "example.com && whoami",
            "example.com\nwhoami",
            "bad_label.example",
            ".example.com",
            "example..com",
            "例子.测试",
        ] {
            let result = validate_trace_request(trace_request(host, 30));
            assert!(result.is_err(), "expected {host:?} to be rejected");
        }
    }

    #[test]
    fn enforces_trace_hop_bounds() {
        assert!(validate_trace_request(trace_request("example.com", 0)).is_err());
        assert!(validate_trace_request(trace_request("example.com", 64)).is_ok());
        assert!(validate_trace_request(trace_request("example.com", 65)).is_err());
    }

    #[test]
    fn accepts_http_and_https_speed_urls() {
        assert!(
            validate_speed_request(speed_request("http://example.com/test.bin", 10, 16)).is_ok()
        );
        assert!(
            validate_speed_request(speed_request("https://example.com/test.bin", 10, 16)).is_ok()
        );
    }

    #[test]
    fn rejects_unsupported_or_credentialed_speed_urls() {
        for url in [
            "file:///tmp/test.bin",
            "ftp://example.com/test.bin",
            "not a url",
            "https://user:secret@example.com/test.bin",
        ] {
            let result = validate_speed_request(speed_request(url, 10, 16));
            assert!(result.is_err(), "expected {url:?} to be rejected");
        }
    }

    #[test]
    fn enforces_speed_test_resource_bounds() {
        assert!(validate_speed_request(speed_request("https://example.com", 0, 16)).is_err());
        assert!(validate_speed_request(speed_request("https://example.com", 301, 16)).is_err());
        assert!(validate_speed_request(speed_request("https://example.com", 10, 0)).is_err());
        assert!(validate_speed_request(speed_request("https://example.com", 10, 1_025)).is_err());
    }

    #[test]
    fn accepts_valid_udp_speed_request() {
        let request = validate_udp_speed_request(udp_request("vps.example.com", 5_201, 10, 100))
            .expect("valid UDP speed request");
        assert_eq!(request.host, "vps.example.com");
    }

    #[test]
    fn udp_speed_request_reuses_strict_host_validation() {
        assert!(
            validate_udp_speed_request(udp_request("example.com && whoami", 5_201, 10, 100))
                .is_err()
        );
    }

    #[test]
    fn enforces_udp_speed_resource_bounds() {
        assert!(validate_udp_speed_request(udp_request("example.com", 0, 10, 100)).is_err());
        assert!(validate_udp_speed_request(udp_request("example.com", 65_536, 10, 100)).is_err());
        assert!(validate_udp_speed_request(udp_request("example.com", 5_201, 0, 100)).is_err());
        assert!(validate_udp_speed_request(udp_request("example.com", 5_201, 61, 100)).is_err());
        assert!(validate_udp_speed_request(udp_request("example.com", 5_201, 10, 0)).is_err());
        assert!(validate_udp_speed_request(udp_request("example.com", 5_201, 10, 10_001)).is_err());
    }
}

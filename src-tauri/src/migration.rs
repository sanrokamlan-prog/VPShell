use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

const MAX_PATH_BYTES: usize = 4096;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FILES: usize = 2000;
const MAX_DEPTH: usize = 12;
const MAX_PROFILES: usize = 2000;
const MAX_REPORTS: usize = 4000;
const MAX_JSON_DEPTH: usize = 16;
const MAX_PREVIEWS: usize = 16;
const PREVIEW_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum MigrationSource {
    OpenSsh,
    Putty,
    Xshell,
    SecureCrt,
    MobaXterm,
    Tabby,
    Termius,
}

impl MigrationSource {
    fn label(self) -> &'static str {
        match self {
            Self::OpenSsh => "OpenSSH",
            Self::Putty => "PuTTY",
            Self::Xshell => "Xshell",
            Self::SecureCrt => "SecureCRT",
            Self::MobaXterm => "MobaXterm",
            Self::Tabby => "Tabby",
            Self::Termius => "Termius",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MigrationPreviewRequest {
    source: MigrationSource,
    path: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImportedHost {
    id: String,
    name: String,
    group: String,
    host: String,
    port: u16,
    username: String,
    environment: String,
    tags: Vec<String>,
    identity_file: Option<String>,
    credential_ref: Option<String>,
    source: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FieldReport {
    field: String,
    status: &'static str,
    message: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ItemReport {
    item: String,
    status: &'static str,
    message: String,
    fields: Vec<FieldReport>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MigrationPreview {
    token: String,
    source: MigrationSource,
    expires_at_epoch_ms: u64,
    files_found: usize,
    profiles_ready: usize,
    imported_fields: usize,
    skipped_fields: usize,
    failed_items: usize,
    reports: Vec<ItemReport>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MigrationApplyResult {
    profiles: Vec<ImportedHost>,
    source: MigrationSource,
    imported_fields: usize,
    skipped_fields: usize,
    failed_items: usize,
    reports: Vec<ItemReport>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MigrationApplyRequest {
    token: String,
}

#[derive(Clone)]
struct FrozenPreview {
    source: MigrationSource,
    created_at: SystemTime,
    profiles: Vec<ImportedHost>,
    imported_fields: usize,
    skipped_fields: usize,
    failed_items: usize,
    reports: Vec<ItemReport>,
}

#[derive(Clone, Default)]
pub(crate) struct MigrationManager {
    previews: Arc<Mutex<HashMap<String, FrozenPreview>>>,
}

#[derive(Default)]
struct ScanResult {
    profiles: Vec<ImportedHost>,
    reports: Vec<ItemReport>,
    files_found: usize,
    limit_exceeded: bool,
}

impl ScanResult {
    fn push_report(&mut self, report: ItemReport) {
        if self.reports.len() >= MAX_REPORTS {
            self.limit_exceeded = true;
        } else {
            self.reports.push(report);
        }
    }
}

#[derive(Default)]
struct Candidate {
    name: String,
    host: String,
    port: Option<u16>,
    username: String,
    group: String,
    tags: Vec<String>,
    fields: Vec<FieldReport>,
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn validate_request(request: &MigrationPreviewRequest) -> Result<PathBuf, String> {
    let value = request.path.trim();
    if value.is_empty() || value.len() > MAX_PATH_BYTES {
        return Err("迁移路径必须为 1–4096 字节".to_string());
    }
    if value
        .chars()
        .any(|character| character == '\0' || character.is_control())
    {
        return Err("迁移路径不能包含控制字符".to_string());
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err("迁移路径必须是绝对路径".to_string());
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("无法读取迁移路径: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Err("迁移根路径不能是符号链接".to_string());
    }
    if !metadata.is_file() && !metadata.is_dir() {
        return Err("迁移路径必须是普通文件或目录".to_string());
    }
    path.canonicalize()
        .map_err(|error| format!("无法规范化迁移路径: {error}"))
}

fn source_accepts(source: MigrationSource, path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match source {
        MigrationSource::OpenSsh => {
            name == "config" || name == "known_hosts" || extension == "conf"
        }
        MigrationSource::Putty => extension == "reg",
        MigrationSource::Xshell => extension == "xsh",
        MigrationSource::SecureCrt => extension == "ini",
        MigrationSource::MobaXterm => extension == "ini" || extension == "mobaconf",
        MigrationSource::Tabby => matches!(extension.as_str(), "yaml" | "yml" | "json"),
        MigrationSource::Termius => matches!(extension.as_str(), "json" | "txt"),
    }
}

fn item_label(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(|value| bounded_label(value, "配置文件"))
        .unwrap_or_else(|| "配置文件".to_string())
}

fn collect_files(root: &Path, source: MigrationSource) -> Result<Vec<PathBuf>, String> {
    if root.is_file() {
        if !source_accepts(source, root) {
            return Err(format!(
                "所选文件不是可识别的 {} 配置/导出格式",
                source.label()
            ));
        }
        return Ok(vec![root.to_path_buf()]);
    }

    let mut files = Vec::new();
    let mut total_bytes = 0_u64;
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    while let Some((directory, depth)) = pending.pop() {
        if depth > MAX_DEPTH {
            return Err(format!("迁移目录嵌套超过 {MAX_DEPTH} 层"));
        }
        let entries =
            fs::read_dir(&directory).map_err(|error| format!("无法读取迁移目录: {error}"))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("无法读取迁移目录项: {error}"))?;
            let file_type = entry
                .file_type()
                .map_err(|error| format!("无法识别迁移目录项: {error}"))?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                pending.push((entry.path(), depth + 1));
            } else if file_type.is_file() && source_accepts(source, &entry.path()) {
                let length = entry
                    .metadata()
                    .map_err(|error| format!("无法读取迁移文件元数据: {error}"))?
                    .len();
                if length > MAX_FILE_BYTES {
                    return Err(format!("迁移文件超过 1 MiB: {}", item_label(&entry.path())));
                }
                total_bytes = total_bytes.saturating_add(length);
                if total_bytes > MAX_TOTAL_BYTES {
                    return Err("迁移文件总量超过 16 MiB".to_string());
                }
                files.push(entry.path());
                if files.len() > MAX_FILES {
                    return Err(format!("迁移文件超过 {MAX_FILES} 个"));
                }
            }
        }
    }
    files.sort();
    if files.is_empty() {
        return Err(format!(
            "目录中没有可识别的 {} 配置/导出文件",
            source.label()
        ));
    }
    Ok(files)
}

fn read_text(path: &Path) -> Result<String, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("无法读取文件元数据: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        return Err("配置必须是小于等于 1 MiB 的普通文件".to_string());
    }
    let bytes = fs::read(path).map_err(|error| format!("无法读取配置文件: {error}"))?;
    let text = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8(bytes[3..].to_vec()).map_err(|_| "配置不是有效 UTF-8".to_string())?
    } else if bytes.starts_with(&[0xFF, 0xFE]) {
        if (bytes.len() - 2) % 2 != 0 {
            return Err("UTF-16LE 配置已截断".to_string());
        }
        let values = bytes[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        String::from_utf16(&values).map_err(|_| "配置不是有效 UTF-16LE".to_string())?
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        if (bytes.len() - 2) % 2 != 0 {
            return Err("UTF-16BE 配置已截断".to_string());
        }
        let values = bytes[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        String::from_utf16(&values).map_err(|_| "配置不是有效 UTF-16BE".to_string())?
    } else {
        String::from_utf8(bytes)
            .map_err(|_| "配置编码必须是 UTF-8、UTF-16LE 或 UTF-16BE".to_string())?
    };
    if text.chars().any(|character| {
        character == '\0' || (character.is_control() && !matches!(character, '\r' | '\n' | '\t'))
    }) {
        return Err("配置包含不支持的控制字符".to_string());
    }
    Ok(text)
}

fn imported(field: &str) -> FieldReport {
    FieldReport {
        field: field.to_string(),
        status: "imported",
        message: "已映射".to_string(),
    }
}

fn skipped(field: &str, message: impl Into<String>) -> FieldReport {
    FieldReport {
        field: field.to_string(),
        status: "skipped",
        message: message.into(),
    }
}

fn failed(field: &str, message: impl Into<String>) -> FieldReport {
    FieldReport {
        field: field.to_string(),
        status: "failed",
        message: message.into(),
    }
}

fn valid_host(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('-')
        && !value.contains(['\r', '\n', '\0', '/', '\\'])
        && !value.chars().any(char::is_whitespace)
}

fn valid_username(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 128
        && !value.contains(['@', '\r', '\n', '\0'])
        && !value.chars().any(char::is_whitespace)
}

fn bounded_label(value: &str, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().any(|character| character.is_control()) {
        fallback.to_string()
    } else {
        trimmed.chars().take(128).collect()
    }
}

fn parse_decimal_port(
    value: Option<&str>,
    field: &str,
    fields: &mut Vec<FieldReport>,
) -> Option<u16> {
    let Some(value) = value else {
        return None;
    };
    match value.parse::<u16>() {
        Ok(port) if port > 0 => {
            fields.push(imported(field));
            Some(port)
        }
        _ => {
            fields.push(failed(field, "端口必须为 1–65535"));
            None
        }
    }
}

fn finalize_candidate(
    candidate: Candidate,
    source: MigrationSource,
    item: String,
    result: &mut ScanResult,
) {
    if result.profiles.len() >= MAX_PROFILES {
        result.limit_exceeded = true;
        return;
    }
    let mut fields = candidate.fields;
    if fields.iter().any(|field| field.status == "failed") {
        result.push_report(ItemReport {
            item,
            status: "failed",
            message: "字段验证失败，未加入预览".to_string(),
            fields,
        });
        return;
    }
    if !valid_host(&candidate.host) {
        fields.push(failed("host", "主机为空、过长或包含不安全字符"));
        result.push_report(ItemReport {
            item,
            status: "failed",
            message: "主机字段无效，未加入预览".to_string(),
            fields,
        });
        return;
    }
    if !valid_username(&candidate.username) {
        fields.push(failed("username", "用户名为空、过长或包含不安全字符"));
        result.push_report(ItemReport {
            item,
            status: "failed",
            message: "用户名字段无效，未加入预览".to_string(),
            fields,
        });
        return;
    }
    let port = candidate.port.unwrap_or(22);
    let name = bounded_label(&candidate.name, &candidate.host);
    let group = bounded_label(&candidate.group, &format!("{} 导入", source.label()));
    result.profiles.push(ImportedHost {
        id: Uuid::new_v4().to_string(),
        name,
        group,
        host: candidate.host.trim().to_string(),
        port,
        username: candidate.username.trim().to_string(),
        environment: "development".to_string(),
        tags: candidate.tags.into_iter().take(16).collect(),
        identity_file: None,
        credential_ref: None,
        source: source.label().to_ascii_lowercase(),
    });
    result.push_report(ItemReport {
        item,
        status: "ready",
        message: "非敏感连接资料已加入预览".to_string(),
        fields,
    });
}

fn shell_words(line: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if let Some(expected) = quote {
            if character == expected {
                quote = None;
            } else {
                current.push(character);
            }
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
        } else if character == '#' {
            break;
        } else if character.is_whitespace() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if escaped || quote.is_some() {
        return Err("引号或转义未闭合".to_string());
    }
    if !current.is_empty() {
        words.push(current);
    }
    Ok(words)
}

#[derive(Default, Clone)]
struct OpenSshBlock {
    aliases: Vec<String>,
    hostname: Option<String>,
    port: Option<u16>,
    username: Option<String>,
    proxy_jump: Option<String>,
    fields: Vec<FieldReport>,
}

fn flush_openssh_block(block: &mut OpenSshBlock, item: &str, result: &mut ScanResult) {
    if block.aliases.is_empty() {
        *block = OpenSshBlock::default();
        return;
    }
    for alias in block.aliases.clone() {
        if alias.contains(['*', '?', '!']) {
            result.push_report(ItemReport {
                item: format!("{item}: Host {alias}"),
                status: "skipped",
                message: "通配或否定 Host 不能无损展开".to_string(),
                fields: vec![skipped("Host", "需要在 OpenSSH 中继续解析")],
            });
            continue;
        }
        let host = block.hostname.clone().unwrap_or_else(|| alias.clone());
        if host.contains('%') {
            result.push_report(ItemReport {
                item: format!("{item}: Host {alias}"),
                status: "skipped",
                message: "包含 OpenSSH 运行时占位符，未猜测展开".to_string(),
                fields: vec![skipped("HostName", "包含 % 占位符")],
            });
            continue;
        }
        let Some(username) = block.username.clone() else {
            result.push_report(ItemReport {
                item: format!("{item}: Host {alias}"),
                status: "failed",
                message: "缺少可导入用户名".to_string(),
                fields: vec![failed("User", "VPShell 主机资料要求显式用户名")],
            });
            continue;
        };
        let mut fields = block.fields.clone();
        fields.push(imported("Host"));
        if block.hostname.is_some() {
            fields.push(imported("HostName"));
        }
        fields.push(imported("User"));
        if block.port.is_some() {
            fields.push(imported("Port"));
        }
        let tags = block
            .proxy_jump
            .as_ref()
            .map(|_| vec!["原配置含 ProxyJump".to_string()])
            .unwrap_or_default();
        finalize_candidate(
            Candidate {
                name: alias.clone(),
                host,
                port: block.port,
                username,
                group: "OpenSSH 导入".to_string(),
                tags,
                fields,
            },
            MigrationSource::OpenSsh,
            format!("{item}: Host {alias}"),
            result,
        );
    }
    *block = OpenSshBlock::default();
}

fn parse_openssh(path: &Path, text: &str, result: &mut ScanResult) {
    let item = item_label(path);
    if path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("known_hosts"))
    {
        let entries = text
            .lines()
            .filter(|line| {
                let line = line.trim();
                !line.is_empty() && !line.starts_with('#')
            })
            .count();
        result.push_report(ItemReport {
            item,
            status: "skipped",
            message: format!(
                "识别 {entries} 条 known_hosts 记录；保持由系统 OpenSSH 管理，不复制或改写"
            ),
            fields: vec![skipped("known_hosts", "主机密钥信任不能由资料迁移隐式授予")],
        });
        return;
    }
    let mut block = OpenSshBlock::default();
    for (line_index, line) in text.lines().enumerate() {
        let words = match shell_words(line) {
            Ok(words) => words,
            Err(message) => {
                result.push_report(ItemReport {
                    item: format!("{item}:{}", line_index + 1),
                    status: "failed",
                    message,
                    fields: Vec::new(),
                });
                continue;
            }
        };
        if words.is_empty() {
            continue;
        }
        let key = words[0].to_ascii_lowercase();
        match key.as_str() {
            "host" => {
                flush_openssh_block(&mut block, &item, result);
                block.aliases = words[1..].iter().take(32).cloned().collect();
            }
            "match" => {
                flush_openssh_block(&mut block, &item, result);
                result.push_report(ItemReport {
                    item: format!("{item}:{}", line_index + 1),
                    status: "skipped",
                    message: "Match 条件不能静态无损求值".to_string(),
                    fields: vec![skipped("Match", "保留给 OpenSSH 运行时")],
                });
            }
            "include" => block.fields.push(skipped(
                "Include",
                "不会递归展开外部路径；请显式选择目标文件/目录",
            )),
            "hostname" if words.len() == 2 => block.hostname = Some(words[1].clone()),
            "port" if words.len() == 2 => match words[1].parse::<u16>() {
                Ok(port) if port > 0 => block.port = Some(port),
                _ => block.fields.push(failed("Port", "端口必须为 1–65535")),
            },
            "user" if words.len() == 2 => block.username = Some(words[1].clone()),
            "identityfile" => block.fields.push(skipped(
                "IdentityFile",
                "私钥路径不自动迁移，请在目标资料中重新选择",
            )),
            "proxyjump" if words.len() == 2 => {
                block.proxy_jump = Some(words[1].clone());
                block.fields.push(skipped(
                    "ProxyJump",
                    "仅保留存在标记；跳板凭据与路由需单独验收",
                ));
            }
            "password" | "identityagent" | "certificatefile" => {
                block.fields.push(skipped(&words[0], "敏感认证字段不迁移"))
            }
            _ => {}
        }
    }
    flush_openssh_block(&mut block, &item, result);
}

fn unescape_reg_string(value: &str) -> Option<String> {
    let value = value.strip_prefix('"')?.strip_suffix('"')?;
    let mut output = String::new();
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character == '\\' {
            match chars.next()? {
                '\\' => output.push('\\'),
                '"' => output.push('"'),
                'n' => output.push('\n'),
                'r' => output.push('\r'),
                other => {
                    output.push('\\');
                    output.push(other);
                }
            }
        } else {
            output.push(character);
        }
    }
    Some(output)
}

fn percent_decode_session(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let pair = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
            if let Some(value) = pair.and_then(|pair| u8::from_str_radix(pair, 16).ok()) {
                output.push(value);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(output).unwrap_or_else(|_| value.to_string())
}

fn parse_putty(path: &Path, text: &str, result: &mut ScanResult) {
    if !text.contains("\\PuTTY\\Sessions\\") {
        result.push_report(ItemReport {
            item: item_label(path),
            status: "failed",
            message: "不是 PuTTY Sessions 注册表导出".to_string(),
            fields: Vec::new(),
        });
        return;
    }
    let mut current: Option<(String, HashMap<String, String>)> = None;
    let flush = |current: &mut Option<(String, HashMap<String, String>)>,
                 result: &mut ScanResult| {
        let Some((name, values)) = current.take() else {
            return;
        };
        if name == "Default%20Settings"
            || values
                .get("Protocol")
                .is_some_and(|value| !value.eq_ignore_ascii_case("ssh"))
        {
            return;
        }
        let mut fields = vec![imported("HostName"), imported("UserName")];
        for secret in [
            "Password",
            "PasswordPlain",
            "PublicKeyFile",
            "DetachedCertificate",
        ] {
            if values.contains_key(secret) {
                fields.push(skipped(secret, "密码、证书或私钥引用不迁移"));
            }
        }
        let port = values.get("PortNumber").and_then(|value| {
            let parsed = value
                .strip_prefix("dword:")
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port > 0);
            if parsed.is_some() {
                fields.push(imported("PortNumber"));
            } else {
                fields.push(failed("PortNumber", "DWORD 端口必须为 1–65535"));
            }
            parsed
        });
        let proxy = values
            .get("ProxyMethod")
            .is_some_and(|value| value != "dword:00000000");
        if proxy {
            fields.push(skipped("ProxyMethod", "仅保留代理存在标记"));
        }
        finalize_candidate(
            Candidate {
                name: percent_decode_session(&name),
                host: values.get("HostName").cloned().unwrap_or_default(),
                port,
                username: values.get("UserName").cloned().unwrap_or_default(),
                group: "PuTTY 导入".to_string(),
                tags: if proxy {
                    vec!["原配置含代理".to_string()]
                } else {
                    Vec::new()
                },
                fields,
            },
            MigrationSource::Putty,
            format!("PuTTY: {}", percent_decode_session(&name)),
            result,
        );
    };
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            flush(&mut current, result);
            let marker = "\\PuTTY\\Sessions\\";
            if let Some(index) = line.find(marker) {
                current = Some((
                    line[index + marker.len()..line.len() - 1].to_string(),
                    HashMap::new(),
                ));
            }
        } else if let Some((_, values)) = current.as_mut() {
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim_matches('"').to_string();
                let value = unescape_reg_string(value).unwrap_or_else(|| value.to_string());
                values.insert(key, value);
            }
        }
    }
    flush(&mut current, result);
}

fn parse_ini(text: &str) -> HashMap<String, HashMap<String, String>> {
    let mut sections = HashMap::<String, HashMap<String, String>>::new();
    let mut section = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with([';', '#']) {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            section = name.trim().to_ascii_lowercase();
        } else if let Some((key, value)) = line.split_once('=') {
            sections.entry(section.clone()).or_default().insert(
                key.trim().to_ascii_lowercase(),
                value.trim().trim_matches('"').to_string(),
            );
        }
    }
    sections
}

fn map_value<'a>(
    sections: &'a HashMap<String, HashMap<String, String>>,
    keys: &[(&str, &str)],
) -> Option<&'a String> {
    keys.iter()
        .find_map(|(section, key)| sections.get(*section).and_then(|values| values.get(*key)))
}

fn parse_xshell(path: &Path, text: &str, result: &mut ScanResult) {
    let sections = parse_ini(text);
    if !sections.contains_key("connection") {
        result.push_report(ItemReport {
            item: item_label(path),
            status: "failed",
            message: "缺少 Xshell [CONNECTION] 区段".to_string(),
            fields: Vec::new(),
        });
        return;
    }
    let protocol = map_value(&sections, &[("connection", "protocol")])
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_else(|| "ssh".to_string());
    if !protocol.starts_with("ssh") {
        result.push_report(ItemReport {
            item: item_label(path),
            status: "skipped",
            message: "只迁移 SSH 会话".to_string(),
            fields: vec![skipped("Protocol", protocol)],
        });
        return;
    }
    let mut fields = vec![imported("Host"), imported("UserName")];
    for key in ["password", "userkey", "masterpassword"] {
        if sections.values().any(|values| values.contains_key(key)) {
            fields.push(skipped(key, "认证秘密或私钥引用不迁移"));
        }
    }
    let port = parse_decimal_port(
        map_value(&sections, &[("connection", "port")]).map(String::as_str),
        "Port",
        &mut fields,
    );
    finalize_candidate(
        Candidate {
            name: path
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("Xshell 会话")
                .to_string(),
            host: map_value(&sections, &[("connection", "host")])
                .cloned()
                .unwrap_or_default(),
            port,
            username: map_value(
                &sections,
                &[
                    ("connection:authentication", "username"),
                    ("connection", "username"),
                ],
            )
            .cloned()
            .unwrap_or_default(),
            group: "Xshell 导入".to_string(),
            tags: Vec::new(),
            fields,
        },
        MigrationSource::Xshell,
        item_label(path),
        result,
    );
}

fn securecrt_values(text: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("S:\"") {
            if let Some((key, value)) = rest.split_once("\"=") {
                values.insert(
                    key.to_ascii_lowercase(),
                    value.trim_matches('"').to_string(),
                );
            }
        } else if let Some(rest) = line.strip_prefix("D:\"") {
            if let Some((key, value)) = rest.split_once("\"=") {
                values.insert(key.to_ascii_lowercase(), format!("hex:{value}"));
            }
        }
    }
    values
}

fn parse_securecrt(path: &Path, text: &str, result: &mut ScanResult) {
    let values = securecrt_values(text);
    if values.is_empty() || !values.contains_key("hostname") {
        result.push_report(ItemReport {
            item: item_label(path),
            status: "failed",
            message: "不是可识别的 SecureCRT 会话 INI".to_string(),
            fields: Vec::new(),
        });
        return;
    }
    let protocol = values
        .get("protocol name")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_else(|| "ssh2".to_string());
    if !protocol.starts_with("ssh") {
        result.push_report(ItemReport {
            item: item_label(path),
            status: "skipped",
            message: "只迁移 SSH 会话".to_string(),
            fields: vec![skipped("Protocol Name", protocol)],
        });
        return;
    }
    let mut fields = vec![imported("Hostname"), imported("Username")];
    for (key, _) in values
        .iter()
        .filter(|(key, _)| key.contains("password") || key.contains("identity"))
    {
        fields.push(skipped(key, "密码或私钥引用不迁移"));
    }
    let port = values.get("[ssh2] port").and_then(|value| {
        let parsed = value
            .strip_prefix("hex:")
            .and_then(|value| u32::from_str_radix(value, 16).ok())
            .and_then(|value| u16::try_from(value).ok())
            .filter(|port| *port > 0);
        if parsed.is_some() {
            fields.push(imported("[SSH2] Port"));
        } else {
            fields.push(failed("[SSH2] Port", "十六进制端口必须为 1–65535"));
        }
        parsed
    });
    finalize_candidate(
        Candidate {
            name: path
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("SecureCRT 会话")
                .to_string(),
            host: values.get("hostname").cloned().unwrap_or_default(),
            port,
            username: values.get("username").cloned().unwrap_or_default(),
            group: "SecureCRT 导入".to_string(),
            tags: Vec::new(),
            fields,
        },
        MigrationSource::SecureCrt,
        item_label(path),
        result,
    );
}

fn parse_mobaxterm(path: &Path, text: &str, result: &mut ScanResult) {
    let sections = parse_ini(text);
    let Some(bookmarks) = sections.get("bookmarks") else {
        result.push_report(ItemReport {
            item: item_label(path),
            status: "failed",
            message: "缺少 MobaXterm [Bookmarks] 区段".to_string(),
            fields: Vec::new(),
        });
        return;
    };
    let group = bookmarks
        .get("subrep")
        .cloned()
        .unwrap_or_else(|| "MobaXterm 导入".to_string());
    let mut found = 0;
    for (name, value) in bookmarks {
        if matches!(name.as_str(), "subrep" | "imgnum") {
            continue;
        }
        let Some(payload) = value.strip_prefix("#109#") else {
            continue;
        };
        let fields = payload.split('%').collect::<Vec<_>>();
        if fields.len() < 4 {
            continue;
        }
        found += 1;
        let mut reports = vec![imported("host"), imported("username")];
        let port = parse_decimal_port(Some(fields[2]), "port", &mut reports);
        reports.push(skipped("password/key", "MobaXterm 密码库和私钥字段不读取"));
        finalize_candidate(
            Candidate {
                name: name.to_string(),
                host: fields[1].to_string(),
                port,
                username: fields[3].to_string(),
                group: group.clone(),
                tags: Vec::new(),
                fields: reports,
            },
            MigrationSource::MobaXterm,
            format!("{}: {name}", item_label(path)),
            result,
        );
    }
    if found == 0 {
        result.push_report(ItemReport {
            item: item_label(path),
            status: "failed",
            message: "未找到可识别的 MobaXterm SSH bookmark (#109#)".to_string(),
            fields: Vec::new(),
        });
    }
}

fn json_string(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str).map(str::to_string))
}

fn json_port(object: &serde_json::Map<String, Value>) -> Option<u16> {
    object.get("port").and_then(|value| {
        value
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
    })
}

fn visit_json_profiles(
    value: &Value,
    depth: usize,
    source: MigrationSource,
    item: &str,
    result: &mut ScanResult,
) -> Result<(), String> {
    if depth > MAX_JSON_DEPTH {
        return Err(format!("JSON 嵌套超过 {MAX_JSON_DEPTH} 层"));
    }
    match value {
        Value::Array(values) => {
            for value in values {
                visit_json_profiles(value, depth + 1, source, item, result)?;
            }
        }
        Value::Object(object) => {
            let host = json_string(object, &["host", "hostname", "address"]);
            let username = json_string(object, &["username", "user"]);
            let kind = json_string(object, &["type", "protocol"])
                .unwrap_or_default()
                .to_ascii_lowercase();
            if host.is_some() && username.is_some() && (kind.is_empty() || kind.contains("ssh")) {
                let mut fields = vec![imported("host"), imported("username")];
                let port = json_port(object);
                if object.contains_key("port") {
                    if port.is_some() {
                        fields.push(imported("port"));
                    } else {
                        fields.push(failed("port", "端口必须为 1–65535"));
                    }
                }
                for key in [
                    "password",
                    "token",
                    "secret",
                    "privateKey",
                    "key",
                    "credential",
                ] {
                    if object.contains_key(key) {
                        fields.push(skipped(key, "秘密、Token 或私钥内容不迁移"));
                    }
                }
                let host = host.unwrap_or_default();
                finalize_candidate(
                    Candidate {
                        name: json_string(object, &["name", "label", "title"])
                            .unwrap_or_else(|| host.clone()),
                        host,
                        port,
                        username: username.unwrap_or_default(),
                        group: json_string(object, &["group", "folder"])
                            .unwrap_or_else(|| format!("{} 导入", source.label())),
                        tags: Vec::new(),
                        fields,
                    },
                    source,
                    item.to_string(),
                    result,
                );
            }
            for child in object.values() {
                visit_json_profiles(child, depth + 1, source, item, result)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn yaml_scalar(value: &str) -> String {
    value.trim().trim_matches(['\'', '"']).to_string()
}

fn parse_tabby_yaml(path: &Path, text: &str, result: &mut ScanResult) {
    let mut candidate: Option<Candidate> = None;
    let mut candidate_indent = 0_usize;
    let flush = |candidate: &mut Option<Candidate>, result: &mut ScanResult| {
        if let Some(candidate) = candidate.take() {
            let name = candidate.name.clone();
            finalize_candidate(
                candidate,
                MigrationSource::Tabby,
                format!("{}: {name}", item_label(path)),
                result,
            );
        }
    };
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let content = trimmed.strip_prefix("- ").unwrap_or(trimmed);
        let Some((key, value)) = content.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = yaml_scalar(value);
        if trimmed.starts_with("- ") && matches!(key, "name" | "type" | "id") {
            flush(&mut candidate, result);
            candidate = Some(Candidate {
                group: "Tabby 导入".to_string(),
                ..Candidate::default()
            });
            candidate_indent = indent;
        }
        let Some(current) = candidate.as_mut() else {
            continue;
        };
        if indent < candidate_indent {
            flush(&mut candidate, result);
            continue;
        }
        match key.to_ascii_lowercase().as_str() {
            "name" | "label" => current.name = value,
            "host" | "hostname" => {
                current.host = value;
                current.fields.push(imported("host"));
            }
            "user" | "username" => {
                current.username = value;
                current.fields.push(imported("user"));
            }
            "port" => match value.parse::<u16>() {
                Ok(port) if port > 0 => {
                    current.port = Some(port);
                    current.fields.push(imported("port"));
                }
                _ => current.fields.push(failed("port", "端口必须为 1–65535")),
            },
            "group" => current.group = value,
            key if key.contains("password") || key.contains("secret") || key.contains("key") => {
                current.fields.push(skipped(key, "秘密或私钥字段不迁移"))
            }
            _ => {}
        }
    }
    flush(&mut candidate, result);
}

fn parse_json_source(path: &Path, text: &str, source: MigrationSource, result: &mut ScanResult) {
    match serde_json::from_str::<Value>(text) {
        Ok(value) => {
            let before = result.profiles.len();
            if let Err(message) = visit_json_profiles(&value, 0, source, &item_label(path), result)
            {
                result.push_report(ItemReport {
                    item: item_label(&path),
                    status: "failed",
                    message,
                    fields: Vec::new(),
                });
            } else if result.profiles.len() == before {
                result.push_report(ItemReport {
                    item: item_label(path),
                    status: "failed",
                    message: format!("未找到可识别的 {} SSH 主机对象", source.label()),
                    fields: Vec::new(),
                });
            }
        }
        Err(error) => result.push_report(ItemReport {
            item: item_label(path),
            status: "failed",
            message: format!("JSON 无效: {error}"),
            fields: Vec::new(),
        }),
    }
}

fn scan(request: &MigrationPreviewRequest) -> Result<ScanResult, String> {
    let root = validate_request(request)?;
    let files = collect_files(&root, request.source)?;
    let mut result = ScanResult {
        files_found: files.len(),
        ..ScanResult::default()
    };
    for path in files {
        let text = match read_text(&path) {
            Ok(text) => text,
            Err(message) => {
                result.push_report(ItemReport {
                    item: item_label(&path),
                    status: "failed",
                    message,
                    fields: Vec::new(),
                });
                continue;
            }
        };
        match request.source {
            MigrationSource::OpenSsh => parse_openssh(&path, &text, &mut result),
            MigrationSource::Putty => parse_putty(&path, &text, &mut result),
            MigrationSource::Xshell => parse_xshell(&path, &text, &mut result),
            MigrationSource::SecureCrt => parse_securecrt(&path, &text, &mut result),
            MigrationSource::MobaXterm => parse_mobaxterm(&path, &text, &mut result),
            MigrationSource::Tabby
                if path
                    .extension()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.eq_ignore_ascii_case("json")) =>
            {
                parse_json_source(&path, &text, request.source, &mut result)
            }
            MigrationSource::Tabby => parse_tabby_yaml(&path, &text, &mut result),
            MigrationSource::Termius => {
                parse_json_source(&path, &text, request.source, &mut result)
            }
        }
    }

    let mut seen = HashSet::new();
    let mut duplicates = Vec::new();
    result.profiles.retain(|profile| {
        let key = format!(
            "{}\0{}\0{}",
            profile.host.to_ascii_lowercase(),
            profile.port,
            profile.username
        );
        if seen.insert(key) {
            true
        } else {
            duplicates.push(profile.name.clone());
            false
        }
    });
    for name in duplicates {
        result.push_report(ItemReport {
            item: name,
            status: "skipped",
            message: "同一批次主机、端口和用户名重复".to_string(),
            fields: vec![skipped("deduplication", "保留首次出现项")],
        });
    }
    if result.limit_exceeded {
        return Err("迁移结果超过 2000 个资料或 4000 条报告".to_string());
    }
    Ok(result)
}

fn counts(reports: &[ItemReport]) -> (usize, usize, usize) {
    let imported_fields = reports
        .iter()
        .flat_map(|report| &report.fields)
        .filter(|field| field.status == "imported")
        .count();
    let skipped_fields = reports
        .iter()
        .flat_map(|report| &report.fields)
        .filter(|field| field.status == "skipped")
        .count();
    let failed_items = reports
        .iter()
        .filter(|report| report.status == "failed")
        .count();
    (imported_fields, skipped_fields, failed_items)
}

impl MigrationManager {
    pub(crate) fn preview(
        &self,
        request: MigrationPreviewRequest,
    ) -> Result<MigrationPreview, String> {
        let scan = scan(&request)?;
        let (imported_fields, skipped_fields, failed_items) = counts(&scan.reports);
        let created_at = SystemTime::now();
        let expires_at_epoch_ms = now_epoch_ms().saturating_add(PREVIEW_TTL.as_millis() as u64);
        let token = Uuid::new_v4().simple().to_string();
        let frozen = FrozenPreview {
            source: request.source,
            created_at,
            profiles: scan.profiles.clone(),
            imported_fields,
            skipped_fields,
            failed_items,
            reports: scan.reports.clone(),
        };
        let mut previews = self
            .previews
            .lock()
            .map_err(|_| "迁移预览管理器不可用".to_string())?;
        previews.retain(|_, preview| {
            created_at
                .duration_since(preview.created_at)
                .unwrap_or_default()
                <= PREVIEW_TTL
        });
        if previews.len() >= MAX_PREVIEWS {
            let oldest = previews
                .iter()
                .min_by_key(|(_, preview)| preview.created_at)
                .map(|(token, _)| token.clone());
            if let Some(oldest) = oldest {
                previews.remove(&oldest);
            }
        }
        previews.insert(token.clone(), frozen);
        Ok(MigrationPreview {
            token,
            source: request.source,
            expires_at_epoch_ms,
            files_found: scan.files_found,
            profiles_ready: scan.profiles.len(),
            imported_fields,
            skipped_fields,
            failed_items,
            reports: scan.reports,
        })
    }

    pub(crate) fn apply(
        &self,
        request: MigrationApplyRequest,
    ) -> Result<MigrationApplyResult, String> {
        if request.token.len() != 32 || !request.token.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("迁移预览令牌无效".to_string());
        }
        let now = SystemTime::now();
        let preview = self
            .previews
            .lock()
            .map_err(|_| "迁移预览管理器不可用".to_string())?
            .remove(&request.token)
            .ok_or_else(|| "迁移预览不存在、已使用或已过期，请重新预览".to_string())?;
        if now.duration_since(preview.created_at).unwrap_or_default() > PREVIEW_TTL {
            return Err("迁移预览已过期，请重新预览".to_string());
        }
        Ok(MigrationApplyResult {
            profiles: preview.profiles,
            source: preview.source,
            imported_fields: preview.imported_fields,
            skipped_fields: preview.skipped_fields,
            failed_items: preview.failed_items,
            reports: preview.reports,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(label: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("vpshell-migration-{label}-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).expect("create temp fixture");
            Self(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn request(source: MigrationSource, path: &Path) -> MigrationPreviewRequest {
        MigrationPreviewRequest {
            source,
            path: path.to_str().expect("utf8 path").to_string(),
        }
    }

    #[test]
    fn openssh_import_is_non_sensitive_and_reports_unmapped_rules() {
        let root = TempDir::new("openssh");
        fs::write(root.0.join("config"), "Host prod\n HostName 192.0.2.20\n User deploy\n Port 2222\n IdentityFile ~/.ssh/id_ed25519\n ProxyJump bastion\nHost *.example\n User root\n") .expect("write config");
        fs::write(root.0.join("known_hosts"), "example ssh-ed25519 AAAATEST\n")
            .expect("write known hosts");
        let scan = scan(&request(MigrationSource::OpenSsh, &root.0)).expect("scan openssh");
        assert_eq!(scan.profiles.len(), 1);
        assert_eq!(scan.profiles[0].host, "192.0.2.20");
        assert_eq!(scan.profiles[0].port, 2222);
        assert!(scan.profiles[0].identity_file.is_none());
        assert!(scan.profiles[0].credential_ref.is_none());
        assert!(
            scan.reports
                .iter()
                .flat_map(|report| &report.fields)
                .any(|field| field.field == "IdentityFile" && field.status == "skipped")
        );
        assert!(
            scan.reports
                .iter()
                .any(|report| report.message.contains("known_hosts"))
        );
        assert!(
            scan.reports
                .iter()
                .any(|report| report.message.contains("通配"))
        );
    }

    #[test]
    fn putty_utf16_export_is_parsed_without_passwords() {
        let root = TempDir::new("putty");
        let content = "Windows Registry Editor Version 5.00\r\n[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\Prod%20Web]\r\n\"HostName\"=\"203.0.113.10\"\r\n\"PortNumber\"=dword:000008ae\r\n\"UserName\"=\"admin\"\r\n\"Protocol\"=\"ssh\"\r\n\"Password\"=\"must-not-import\"\r\n";
        let mut encoded = vec![0xFF, 0xFE];
        for unit in content.encode_utf16() {
            encoded.extend_from_slice(&unit.to_le_bytes());
        }
        let path = root.0.join("putty.reg");
        fs::write(&path, encoded).expect("write reg");
        let scan = scan(&request(MigrationSource::Putty, &path)).expect("scan putty");
        assert_eq!(scan.profiles.len(), 1);
        assert_eq!(scan.profiles[0].name, "Prod Web");
        assert_eq!(scan.profiles[0].port, 2222);
        assert!(
            scan.reports
                .iter()
                .flat_map(|report| &report.fields)
                .any(|field| field.field == "Password" && field.status == "skipped")
        );
    }

    #[test]
    fn ini_adapters_parse_only_their_audited_ssh_shapes() {
        let root = TempDir::new("ini");
        let xsh = root.0.join("prod.xsh");
        fs::write(&xsh, "[CONNECTION]\nProtocol=SSH\nHost=198.51.100.2\nPort=22\n[CONNECTION:AUTHENTICATION]\nUserName=ops\nPassword=encrypted\n").expect("write xsh");
        assert_eq!(
            scan(&request(MigrationSource::Xshell, &xsh))
                .expect("xshell")
                .profiles
                .len(),
            1
        );

        let crt = root.0.join("prod.ini");
        fs::write(&crt, "S:\"Protocol Name\"=SSH2\nS:\"Hostname\"=198.51.100.3\nS:\"Username\"=ops\nD:\"[SSH2] Port\"=00000016\nS:\"Password V2\"=encrypted\n").expect("write crt");
        assert_eq!(
            scan(&request(MigrationSource::SecureCrt, &crt))
                .expect("securecrt")
                .profiles
                .len(),
            1
        );

        let moba = root.0.join("MobaXterm.ini");
        fs::write(
            &moba,
            "[Bookmarks]\nSubRep=Imported\nProd=#109#0%198.51.100.4%22%ops%encrypted\n",
        )
        .expect("write moba");
        assert_eq!(
            scan(&request(MigrationSource::MobaXterm, &moba))
                .expect("moba")
                .profiles
                .len(),
            1
        );
    }

    #[test]
    fn tabby_and_termius_adapters_skip_secret_material() {
        let root = TempDir::new("structured");
        let tabby = root.0.join("tabby.yaml");
        fs::write(&tabby, "profiles:\n  - name: Tabby prod\n    type: ssh\n    options:\n      host: 192.0.2.30\n      port: 2200\n      user: dev\n      privateKey: SECRET\n").expect("write tabby");
        let tabby_scan = scan(&request(MigrationSource::Tabby, &tabby)).expect("tabby");
        assert_eq!(tabby_scan.profiles.len(), 1);
        assert!(
            tabby_scan
                .reports
                .iter()
                .flat_map(|report| &report.fields)
                .any(|field| field.field.eq_ignore_ascii_case("privateKey")
                    && field.status == "skipped")
        );

        let termius = root.0.join("termius.json");
        fs::write(&termius, r#"{"hosts":[{"label":"Termius prod","address":"192.0.2.31","username":"dev","port":22,"password":"SECRET","token":"SECRET"}]}"#).expect("write termius");
        let termius_scan = scan(&request(MigrationSource::Termius, &termius)).expect("termius");
        assert_eq!(termius_scan.profiles.len(), 1);
        assert!(
            termius_scan
                .reports
                .iter()
                .flat_map(|report| &report.fields)
                .filter(|field| field.status == "skipped")
                .count()
                >= 2
        );
    }

    #[test]
    fn path_encoding_depth_size_and_duplicate_limits_are_enforced() {
        let manager = MigrationManager::default();
        assert!(
            manager
                .preview(MigrationPreviewRequest {
                    source: MigrationSource::OpenSsh,
                    path: "relative/config".to_string()
                })
                .is_err()
        );
        let root = TempDir::new("bounds");
        let bad = root.0.join("config");
        fs::write(&bad, [0xFF, 0x00, 0xFF]).expect("write bad encoding");
        let preview = manager
            .preview(request(MigrationSource::OpenSsh, &bad))
            .expect("per-file encoding failure is reported");
        assert_eq!(preview.failed_items, 1);
        assert_eq!(preview.profiles_ready, 0);

        let duplicate = root.0.join("duplicate.json");
        fs::write(
            &duplicate,
            r#"[{"host":"192.0.2.40","username":"u"},{"host":"192.0.2.40","username":"u"}]"#,
        )
        .expect("write duplicate");
        let preview = manager
            .preview(request(MigrationSource::Termius, &duplicate))
            .expect("preview duplicates");
        assert_eq!(preview.profiles_ready, 1);
        assert!(
            preview
                .reports
                .iter()
                .any(|report| report.message.contains("重复"))
        );

        let mut nested = root.0.join("nested");
        fs::create_dir_all(&nested).expect("create nested root");
        for _ in 0..=MAX_DEPTH {
            nested = nested.join("level");
            fs::create_dir(&nested).expect("create nested level");
        }
        assert!(collect_files(&root.0.join("nested"), MigrationSource::Termius).is_err());

        let deep_json = root.0.join("deep.json");
        fs::write(
            &deep_json,
            format!(
                "{}null{}",
                "[".repeat(MAX_JSON_DEPTH + 1),
                "]".repeat(MAX_JSON_DEPTH + 1)
            ),
        )
        .expect("write deep json");
        let preview = manager
            .preview(request(MigrationSource::Termius, &deep_json))
            .expect("deep JSON is reported safely");
        assert_eq!(preview.failed_items, 1);

        let too_large = root.0.join("too-large.json");
        fs::write(&too_large, vec![b' '; (MAX_FILE_BYTES as usize) + 1]).expect("write large file");
        let preview = manager
            .preview(request(MigrationSource::Termius, &too_large))
            .expect("large file failure is reported");
        assert_eq!(preview.failed_items, 1);

        let total_root = root.0.join("total");
        fs::create_dir(&total_root).expect("create total root");
        for index in 0..17 {
            fs::write(
                total_root.join(format!("{index}.json")),
                vec![b' '; MAX_FILE_BYTES as usize],
            )
            .expect("write total fixture");
        }
        assert!(collect_files(&total_root, MigrationSource::Termius).is_err());
    }

    #[test]
    fn invalid_ports_and_report_overflow_never_silently_fallback() {
        let root = TempDir::new("validation");
        let invalid_port = root.0.join("invalid.xsh");
        fs::write(
            &invalid_port,
            "[CONNECTION]\nProtocol=SSH\nHost=192.0.2.80\nPort=70000\n[CONNECTION:AUTHENTICATION]\nUserName=ops\n",
        )
        .expect("write invalid port");
        let result =
            scan(&request(MigrationSource::Xshell, &invalid_port)).expect("scan invalid port");
        assert!(result.profiles.is_empty());
        assert!(
            result
                .reports
                .iter()
                .any(|report| report.status == "failed")
        );

        let noisy = root.0.join("config");
        fs::write(&noisy, "Host \"\n".repeat(MAX_REPORTS + 1)).expect("write bounded noisy file");
        assert!(scan(&request(MigrationSource::OpenSsh, &noisy)).is_err());

        let count_root = root.0.join("count");
        fs::create_dir(&count_root).expect("create count root");
        for index in 0..=MAX_FILES {
            fs::write(count_root.join(format!("count-{index}.json")), "[]")
                .expect("write count fixture");
        }
        assert!(collect_files(&count_root, MigrationSource::Termius).is_err());
    }

    #[test]
    fn preview_is_frozen_single_use_bounded_and_expiring() {
        let root = TempDir::new("preview");
        let path = root.0.join("hosts.json");
        fs::write(&path, r#"[{"host":"192.0.2.50","username":"u"}]"#).expect("write fixture");
        let manager = MigrationManager::default();
        let preview = manager
            .preview(request(MigrationSource::Termius, &path))
            .expect("preview");
        fs::write(&path, r#"[{"host":"changed.example","username":"u"}]"#).expect("mutate source");
        let applied = manager
            .apply(MigrationApplyRequest {
                token: preview.token.clone(),
            })
            .expect("apply frozen preview");
        assert_eq!(applied.profiles[0].host, "192.0.2.50");
        assert!(
            manager
                .apply(MigrationApplyRequest {
                    token: preview.token
                })
                .is_err()
        );

        for index in 0..(MAX_PREVIEWS + 2) {
            fs::write(
                &path,
                format!(r#"[{{"host":"192.0.2.{}","username":"u"}}]"#, 60 + index),
            )
            .expect("rewrite fixture");
            manager
                .preview(request(MigrationSource::Termius, &path))
                .expect("bounded preview");
        }
        assert_eq!(
            manager.previews.lock().expect("preview lock").len(),
            MAX_PREVIEWS
        );

        let expiring = manager
            .preview(request(MigrationSource::Termius, &path))
            .expect("expiring preview");
        manager
            .previews
            .lock()
            .expect("preview lock")
            .get_mut(&expiring.token)
            .expect("stored preview")
            .created_at = SystemTime::now() - PREVIEW_TTL - Duration::from_secs(1);
        assert!(
            manager
                .apply(MigrationApplyRequest {
                    token: expiring.token
                })
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_roots_and_entries_are_not_followed() {
        use std::os::unix::fs::symlink;
        let root = TempDir::new("symlink");
        let outside = TempDir::new("outside");
        fs::write(
            outside.0.join("hosts.json"),
            r#"[{"host":"192.0.2.70","username":"u"}]"#,
        )
        .expect("write outside");
        symlink(&outside.0, root.0.join("linked-dir")).expect("link directory");
        let direct = root.0.join("linked.json");
        symlink(outside.0.join("hosts.json"), &direct).expect("link file");
        assert!(scan(&request(MigrationSource::Termius, &direct)).is_err());
        assert!(
            collect_files(&root.0, MigrationSource::Termius)
                .unwrap_or_default()
                .is_empty()
        );
    }
}

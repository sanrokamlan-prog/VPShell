use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::Serialize;

const OSC_PREFIX: &[u8] = b"\x1b]777;vpshell;";
const OSC_TERMINATOR: u8 = 0x07;
const MAX_FRAME_BYTES: usize = 8 * 1024;
const MAX_CONTEXT_DEPTH: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ShellContext {
    pub(crate) hostname: String,
    pub(crate) username: String,
    pub(crate) cwd: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TerminalContextEvent {
    pub(crate) session_id: String,
    pub(crate) stack: Vec<ShellContext>,
    pub(crate) warning: Option<String>,
}

pub(crate) struct ShellIntegrationParser {
    token: String,
    pending: Vec<u8>,
    stack: Vec<ShellContext>,
    revision: u64,
}

impl ShellIntegrationParser {
    pub(crate) fn new() -> Self {
        Self {
            token: uuid::Uuid::new_v4().simple().to_string(),
            pending: Vec::new(),
            stack: Vec::new(),
            revision: 0,
        }
    }

    #[cfg(test)]
    fn with_token(token: &str) -> Self {
        Self {
            token: token.to_string(),
            pending: Vec::new(),
            stack: Vec::new(),
            revision: 0,
        }
    }

    pub(crate) fn activation_command(&self) -> String {
        format!(
            "VPSHELL_SI_TOKEN='{}'; vpshell_si_emit() {{ if ! command -v base64 >/dev/null 2>&1; then return; fi; _vpsh=$(command hostname 2>/dev/null | base64 | tr -d '\\r\\n'); _vpsu=$(command id -un 2>/dev/null | base64 | tr -d '\\r\\n'); _vpsc=$(command pwd -P 2>/dev/null | base64 | tr -d '\\r\\n'); printf '\\033]777;vpshell;%s;%s;%s;%s\\007' \"$VPSHELL_SI_TOKEN\" \"$_vpsh\" \"$_vpsu\" \"$_vpsc\"; unset _vpsh _vpsu _vpsc; }}; if [ -n \"${{ZSH_VERSION-}}\" ]; then case \" ${{precmd_functions[*]-}} \" in *' vpshell_si_emit '*) ;; *) precmd_functions+=(vpshell_si_emit) ;; esac; else case \";${{PROMPT_COMMAND-}};\" in *';vpshell_si_emit;'*) ;; *) PROMPT_COMMAND=\"vpshell_si_emit${{PROMPT_COMMAND:+;$PROMPT_COMMAND}}\" ;; esac; fi; vpshell_si_emit\r",
            self.token
        )
    }

    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) fn feed(
        &mut self,
        bytes: &[u8],
    ) -> (Vec<u8>, Vec<(Vec<ShellContext>, Option<String>)>) {
        self.pending.extend_from_slice(bytes);
        let mut output = Vec::with_capacity(bytes.len());
        let mut updates = Vec::new();

        loop {
            let Some(start) = find_bytes(&self.pending, OSC_PREFIX) else {
                let retained = partial_prefix_len(&self.pending, OSC_PREFIX);
                let emit_length = self.pending.len().saturating_sub(retained);
                output.extend(self.pending.drain(..emit_length));
                break;
            };
            output.extend(self.pending.drain(..start));
            let Some(relative_end) = self.pending[OSC_PREFIX.len()..]
                .iter()
                .position(|byte| *byte == OSC_TERMINATOR)
            else {
                if self.pending.len() > MAX_FRAME_BYTES {
                    output.push(self.pending.remove(0));
                    continue;
                }
                break;
            };
            let end = OSC_PREFIX.len() + relative_end;
            let frame = self.pending.drain(..=end).collect::<Vec<_>>();
            match parse_frame(&frame, &self.token) {
                Ok(context) => updates.push(self.apply_context(context)),
                Err(_) => output.extend(frame),
            }
        }
        (output, updates)
    }

    fn apply_context(&mut self, context: ShellContext) -> (Vec<ShellContext>, Option<String>) {
        if let Some(position) = self.stack.iter().position(|existing| {
            existing.hostname == context.hostname && existing.username == context.username
        }) {
            self.stack.truncate(position + 1);
            self.stack[position] = context;
            self.revision = self.revision.wrapping_add(1);
            return (self.stack.clone(), None);
        }
        if self.stack.len() >= MAX_CONTEXT_DEPTH {
            return (
                self.stack.clone(),
                Some(format!(
                    "Shell 主机上下文最多保留 {MAX_CONTEXT_DEPTH} 层，已忽略更深层上报"
                )),
            );
        }
        self.stack.push(context);
        self.revision = self.revision.wrapping_add(1);
        (self.stack.clone(), None)
    }
}

fn parse_frame(frame: &[u8], token: &str) -> Result<ShellContext, String> {
    if !frame.starts_with(OSC_PREFIX) || frame.last() != Some(&OSC_TERMINATOR) {
        return Err("Shell Integration 帧边界无效".to_string());
    }
    let body = std::str::from_utf8(&frame[OSC_PREFIX.len()..frame.len() - 1])
        .map_err(|_| "Shell Integration 帧不是 UTF-8".to_string())?;
    let fields = body.split(';').collect::<Vec<_>>();
    if fields.len() != 4 || fields[0] != token {
        return Err("Shell Integration 会话令牌不匹配".to_string());
    }
    let hostname = decode_field(fields[1], 255, "hostname")?;
    let username = decode_field(fields[2], 128, "username")?;
    let cwd = decode_field(fields[3], 4096, "cwd")?;
    if hostname.is_empty()
        || username.is_empty()
        || !cwd.starts_with('/')
        || hostname.chars().any(char::is_control)
        || username.chars().any(char::is_control)
        || cwd.chars().any(char::is_control)
    {
        return Err("Shell Integration 上下文字段无效".to_string());
    }
    Ok(ShellContext {
        hostname,
        username,
        cwd,
    })
}

fn decode_field(value: &str, maximum: usize, label: &str) -> Result<String, String> {
    if value.len() > maximum.saturating_mul(2).saturating_add(8) {
        return Err(format!("Shell Integration {label} 字段过长"));
    }
    let bytes = BASE64_STANDARD
        .decode(value)
        .map_err(|_| format!("Shell Integration {label} 编码无效"))?;
    if bytes.len() > maximum {
        return Err(format!("Shell Integration {label} 字段过长"));
    }
    String::from_utf8(bytes).map_err(|_| format!("Shell Integration {label} 不是 UTF-8"))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn partial_prefix_len(bytes: &[u8], prefix: &[u8]) -> usize {
    let maximum = bytes.len().min(prefix.len().saturating_sub(1));
    (1..=maximum)
        .rev()
        .find(|length| bytes[bytes.len() - length..] == prefix[..*length])
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn frame(host: &str, user: &str, cwd: &str, token: &str) -> Vec<u8> {
        format!(
            "\x1b]777;vpshell;{};{};{};{}\x07",
            token,
            BASE64_STANDARD.encode(host),
            BASE64_STANDARD.encode(user),
            BASE64_STANDARD.encode(cwd)
        )
        .into_bytes()
    }

    #[test]
    fn parses_chunked_authenticated_frames_without_showing_protocol_bytes() {
        let mut parser = ShellIntegrationParser::with_token(TOKEN);
        let bytes = frame("web-01", "ops", "/srv/app", TOKEN);
        let split = bytes.len() / 2;
        let (first_output, first_updates) = parser.feed(&bytes[..split]);
        assert!(first_output.is_empty());
        assert!(first_updates.is_empty());
        let (second_output, second_updates) = parser.feed(&bytes[split..]);
        assert!(second_output.is_empty());
        assert_eq!(second_updates[0].0[0].hostname, "web-01");
        assert_eq!(second_updates[0].0[0].cwd, "/srv/app");
    }

    #[test]
    fn preserves_spoofed_or_malformed_frames_as_terminal_output() {
        let mut parser = ShellIntegrationParser::with_token(TOKEN);
        let spoofed = frame("evil", "root", "/", "ffffffffffffffffffffffffffffffff");
        let (output, updates) = parser.feed(&spoofed);
        assert_eq!(output, spoofed);
        assert!(updates.is_empty());

        let oversized = format!("\x1b]777;vpshell;{TOKEN};{}", "A".repeat(MAX_FRAME_BYTES));
        let (output, updates) = parser.feed(oversized.as_bytes());
        assert!(!output.is_empty());
        assert!(updates.is_empty());
    }

    #[test]
    fn context_stack_pushes_nested_hosts_and_pops_to_known_ancestors() {
        let mut parser = ShellIntegrationParser::with_token(TOKEN);
        for (host, cwd) in [("edge", "/home/ops"), ("db", "/var/lib"), ("edge", "/srv")] {
            let (_, updates) = parser.feed(&frame(host, "ops", cwd, TOKEN));
            let stack = &updates[0].0;
            if host == "db" {
                assert_eq!(stack.len(), 2);
            }
        }
        assert_eq!(parser.stack.len(), 1);
        assert_eq!(parser.stack[0].hostname, "edge");
        assert_eq!(parser.stack[0].cwd, "/srv");
    }

    #[test]
    fn context_depth_is_bounded_with_an_explainable_warning() {
        let mut parser = ShellIntegrationParser::with_token(TOKEN);
        for index in 0..MAX_CONTEXT_DEPTH {
            let (_, updates) = parser.feed(&frame(&format!("host-{index}"), "ops", "/tmp", TOKEN));
            assert!(updates[0].1.is_none());
        }
        let (_, updates) = parser.feed(&frame("too-deep", "ops", "/tmp", TOKEN));
        assert_eq!(updates[0].0.len(), MAX_CONTEXT_DEPTH);
        assert!(updates[0].1.as_deref().unwrap().contains("最多保留 8 层"));
    }

    #[test]
    fn activation_command_contains_only_generated_protocol_and_fixed_shell_code() {
        let parser = ShellIntegrationParser::with_token(TOKEN);
        let command = parser.activation_command();
        assert!(command.contains(TOKEN));
        assert!(command.contains("vpshell_si_emit"));
        assert!(!command.contains("credential"));
        assert!(command.ends_with('\r'));
    }
}

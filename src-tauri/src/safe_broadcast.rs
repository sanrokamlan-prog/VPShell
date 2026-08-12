use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

const MAX_BROADCAST_TARGETS: usize = 32;
const MAX_BROADCAST_COMMAND_BYTES: usize = 4096;
const MAX_PENDING_PREVIEWS: usize = 32;
const PREVIEW_TTL_MILLIS: u64 = 2 * 60 * 1000;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BroadcastTargetRequest {
    pub(crate) session_id: String,
    pub(crate) label: String,
    pub(crate) environment: String,
}

#[derive(Clone, Debug)]
pub(crate) struct VerifiedBroadcastTarget {
    pub(crate) session_id: String,
    pub(crate) label: String,
    pub(crate) environment: String,
    pub(crate) context_revision: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BroadcastPreviewTarget {
    pub(crate) session_id: String,
    pub(crate) label: String,
    pub(crate) environment: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BroadcastPreview {
    pub(crate) confirmation_token: String,
    pub(crate) command: String,
    pub(crate) targets: Vec<BroadcastPreviewTarget>,
    pub(crate) risk: String,
    pub(crate) warning: String,
    pub(crate) production_targets: usize,
    pub(crate) expires_at: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BroadcastItemResult {
    pub(crate) session_id: String,
    pub(crate) label: String,
    pub(crate) outcome: String,
    pub(crate) message: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BroadcastResult {
    pub(crate) outcome: String,
    pub(crate) succeeded: usize,
    pub(crate) failed: usize,
    pub(crate) skipped: usize,
    pub(crate) items: Vec<BroadcastItemResult>,
}

#[derive(Clone)]
pub(crate) struct PendingBroadcast {
    pub(crate) command: String,
    pub(crate) targets: Vec<VerifiedBroadcastTarget>,
}

struct PendingRecord {
    command: String,
    targets: Vec<VerifiedBroadcastTarget>,
    expires_at: u64,
}

#[derive(Clone, Default)]
pub(crate) struct SafeBroadcastManager {
    pending: Arc<Mutex<HashMap<String, PendingRecord>>>,
}

impl SafeBroadcastManager {
    fn lock(&self) -> Result<MutexGuard<'_, HashMap<String, PendingRecord>>, String> {
        self.pending
            .lock()
            .map_err(|_| "安全广播预览状态已损坏".to_string())
    }

    pub(crate) fn preview(
        &self,
        command: String,
        targets: Vec<VerifiedBroadcastTarget>,
    ) -> Result<BroadcastPreview, String> {
        validate_command(&command)?;
        validate_targets(&targets)?;
        let risk = classify_command(&command)?;
        let now = now_millis();
        let expires_at = now.saturating_add(PREVIEW_TTL_MILLIS);
        let token = uuid::Uuid::new_v4().to_string();
        let production_targets = targets
            .iter()
            .filter(|target| target.environment == "production")
            .count();
        let preview_targets = targets
            .iter()
            .map(|target| BroadcastPreviewTarget {
                session_id: target.session_id.clone(),
                label: target.label.clone(),
                environment: target.environment.clone(),
            })
            .collect();
        let warning = if production_targets > 0 {
            format!("包含 {production_targets} 个生产目标；确认后仅向此冻结清单发送一次")
        } else {
            "确认后仅向此冻结清单发送一次；目标或上下文变化将逐项跳过".to_string()
        };

        let mut pending = self.lock()?;
        pending.retain(|_, record| record.expires_at > now);
        if pending.len() >= MAX_PENDING_PREVIEWS {
            return Err(format!("待确认广播不能超过 {MAX_PENDING_PREVIEWS} 个"));
        }
        pending.insert(
            token.clone(),
            PendingRecord {
                command: command.clone(),
                targets,
                expires_at,
            },
        );
        Ok(BroadcastPreview {
            confirmation_token: token,
            command,
            targets: preview_targets,
            risk: risk.to_string(),
            warning,
            production_targets,
            expires_at,
        })
    }

    pub(crate) fn consume(&self, token: &str) -> Result<PendingBroadcast, String> {
        if token.len() != 36
            || !token
                .chars()
                .all(|character| character.is_ascii_hexdigit() || character == '-')
        {
            return Err("广播确认令牌格式无效".to_string());
        }
        let record = self
            .lock()?
            .remove(token)
            .ok_or_else(|| "广播确认已失效、过期或使用过".to_string())?;
        if record.expires_at <= now_millis() {
            return Err("广播确认已超过两分钟，请重新预览".to_string());
        }
        Ok(PendingBroadcast {
            command: record.command,
            targets: record.targets,
        })
    }
}

fn validate_command(command: &str) -> Result<(), String> {
    if command.trim().is_empty()
        || command.len() > MAX_BROADCAST_COMMAND_BYTES
        || command
            .chars()
            .any(|character| character.is_control() || matches!(character, '\n' | '\r'))
    {
        return Err("广播命令为空、过长或包含控制字符".to_string());
    }
    Ok(())
}

fn validate_targets(targets: &[VerifiedBroadcastTarget]) -> Result<(), String> {
    if targets.is_empty() || targets.len() > MAX_BROADCAST_TARGETS {
        return Err(format!(
            "广播目标必须在 1 到 {MAX_BROADCAST_TARGETS} 个之间"
        ));
    }
    let mut unique = HashSet::new();
    for target in targets {
        if target.session_id.is_empty()
            || target.session_id.len() > 128
            || target.label.is_empty()
            || target.label.len() > 128
            || target.label.chars().any(char::is_control)
            || !matches!(
                target.environment.as_str(),
                "production" | "staging" | "development"
            )
            || !unique.insert(&target.session_id)
        {
            return Err("广播目标字段无效或包含重复会话".to_string());
        }
    }
    Ok(())
}

fn classify_command(command: &str) -> Result<&'static str, String> {
    let normalized = command.trim().to_ascii_lowercase();
    let words = shell_words(&normalized);
    let authentication_commands = ["sudo", "su", "passwd", "ssh", "sftp", "scp", "sshpass"];
    if authentication_commands
        .iter()
        .any(|command| words.iter().any(|word| word == command))
        || normalized.contains("mysql -p")
        || normalized.contains("psql -w")
    {
        return Err(
            "安全广播拒绝可能请求密码、口令或交互认证的命令；请在单个终端中执行".to_string(),
        );
    }
    let destructive = [
        "dd if=",
        "iptables -f",
        "nft flush",
        ":(){",
        "chmod -r 777 /",
        "find / -delete",
    ];
    let recursive_force_rm = words
        .iter()
        .position(|word| word == "rm")
        .is_some_and(|position| {
            let arguments = &words[position + 1..];
            let short_flags = arguments
                .iter()
                .filter(|argument| argument.starts_with('-') && !argument.starts_with("--"))
                .flat_map(|argument| argument.trim_start_matches('-').chars())
                .collect::<String>();
            let recursive =
                short_flags.contains('r') || arguments.iter().any(|word| word == "--recursive");
            let force = short_flags.contains('f') || arguments.iter().any(|word| word == "--force");
            recursive && force
        });
    let download_to_shell = (words.iter().any(|word| word == "curl")
        || words.iter().any(|word| word == "wget"))
        && (normalized.contains("| sh")
            || normalized.contains("|sh")
            || normalized.contains("| bash")
            || normalized.contains("|bash"));
    if recursive_force_rm
        || download_to_shell
        || destructive
            .iter()
            .any(|pattern| normalized.contains(pattern))
        || words.iter().any(|word| {
            matches!(
                word.as_str(),
                "wipefs" | "shutdown" | "poweroff" | "reboot" | "halt"
            ) || word == "mkfs"
                || word.starts_with("mkfs.")
        })
    {
        return Err("安全广播已阻止已知破坏性命令；请逐台核对后在单个终端中执行".to_string());
    }
    let elevated_risk = [
        "systemctl restart",
        "systemctl stop",
        "service ",
        "apt remove",
        "dnf remove",
        "yum remove",
        "docker system prune",
        "kubectl delete",
    ];
    Ok(
        if elevated_risk
            .iter()
            .any(|pattern| normalized.contains(pattern))
        {
            "high"
        } else {
            "normal"
        },
    )
}

fn shell_words(command: &str) -> Vec<String> {
    command
        .split(|character: char| {
            character.is_whitespace() || matches!(character, ';' | '|' | '&' | '(' | ')')
        })
        .filter(|word| !word.is_empty())
        .map(str::to_string)
        .collect()
}

pub(crate) fn summarize_results(items: Vec<BroadcastItemResult>) -> BroadcastResult {
    let succeeded = items
        .iter()
        .filter(|item| item.outcome == "succeeded")
        .count();
    let failed = items.iter().filter(|item| item.outcome == "failed").count();
    let skipped = items
        .iter()
        .filter(|item| item.outcome == "skipped")
        .count();
    let outcome = if failed == 0 && skipped == 0 {
        "completed"
    } else if succeeded == 0 && failed == 0 {
        "skipped"
    } else if succeeded == 0 {
        "failed"
    } else {
        "partial"
    };
    BroadcastResult {
        outcome: outcome.to_string(),
        succeeded,
        failed,
        skipped,
        items,
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(id: &str, environment: &str, revision: u64) -> VerifiedBroadcastTarget {
        VerifiedBroadcastTarget {
            session_id: id.to_string(),
            label: format!("host-{id}"),
            environment: environment.to_string(),
            context_revision: revision,
        }
    }

    #[test]
    fn rejects_authentication_and_destructive_commands() {
        for command in [
            "sudo systemctl restart nginx",
            "ssh root@example.com",
            "passwd",
            "rm -rf /var/lib/app",
            "rm -r -f /var/lib/app",
            "rm --recursive --force /var/lib/app",
            "mkfs.ext4 /dev/sdb",
            "curl https://example.invalid/install | bash",
        ] {
            assert!(classify_command(command).is_err(), "{command}");
        }
        assert_eq!(classify_command("systemctl restart nginx").unwrap(), "high");
        assert_eq!(classify_command("uptime").unwrap(), "normal");
    }

    #[test]
    fn preview_freezes_targets_requires_production_warning_and_is_single_use() {
        let manager = SafeBroadcastManager::default();
        let preview = manager
            .preview(
                "uptime".to_string(),
                vec![
                    target("one", "production", 3),
                    target("two", "development", 5),
                ],
            )
            .unwrap();
        assert_eq!(preview.production_targets, 1);
        assert_eq!(preview.targets.len(), 2);
        assert!(preview.warning.contains("生产目标"));

        let pending = manager.consume(&preview.confirmation_token).unwrap();
        assert_eq!(pending.command, "uptime");
        assert_eq!(pending.targets[0].context_revision, 3);
        assert!(manager.consume(&preview.confirmation_token).is_err());
    }

    #[test]
    fn target_and_command_limits_are_hard() {
        let manager = SafeBroadcastManager::default();
        assert!(
            manager
                .preview("\n".to_string(), vec![target("one", "development", 0)])
                .is_err()
        );
        assert!(
            manager
                .preview(
                    "uptime".to_string(),
                    vec![
                        target("same", "development", 0),
                        target("same", "development", 0)
                    ],
                )
                .is_err()
        );
        assert!(
            manager
                .preview(
                    "x".repeat(MAX_BROADCAST_COMMAND_BYTES + 1),
                    vec![target("one", "development", 0)],
                )
                .is_err()
        );
    }

    #[test]
    fn partial_results_never_report_full_success() {
        let result = summarize_results(vec![
            BroadcastItemResult {
                session_id: "one".to_string(),
                label: "one".to_string(),
                outcome: "succeeded".to_string(),
                message: "sent".to_string(),
            },
            BroadcastItemResult {
                session_id: "two".to_string(),
                label: "two".to_string(),
                outcome: "skipped".to_string(),
                message: "context changed".to_string(),
            },
            BroadcastItemResult {
                session_id: "three".to_string(),
                label: "three".to_string(),
                outcome: "failed".to_string(),
                message: "write failed".to_string(),
            },
        ]);
        assert_eq!(result.outcome, "partial");
        assert_eq!((result.succeeded, result.failed, result.skipped), (1, 1, 1));
    }
}

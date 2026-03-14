//! User decision tracking for auto-learning rules.

use clx_core::config::Config;
use clx_core::storage::Storage;
use clx_core::types::{LearnedRule, RuleType};
use tracing::{debug, warn};

/// Commands that should never be auto-whitelisted due to destructive potential.
///
/// Even if the user approves these commands repeatedly, they remain subject to
/// manual confirmation. This prevents overly broad patterns (e.g. `Bash(rm:-i *)`)
/// from silently whitelisting destructive variants (e.g. `rm -rf /`).
const NEVER_AUTO_WHITELIST: &[&str] = &[
    "rm",
    "rmdir",
    "dd",
    "mkfs",
    "fdisk",
    "chmod",
    "chown",
    "chgrp",
    "kill",
    "killall",
    "pkill",
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "iptables",
    "ip6tables",
    "mount",
    "umount",
    "systemctl",
    "service",
];

/// Check whether the base command (first word) of a command string is restricted
/// from auto-whitelisting.
pub(crate) fn is_restricted_command(command: &str) -> bool {
    let base_cmd = command.split_whitespace().next().unwrap_or("");
    NEVER_AUTO_WHITELIST.contains(&base_cmd)
}

/// Commands that should never be auto-blacklisted because they are critical
/// development tools. Blocking them would cripple normal development workflows.
const NEVER_AUTO_BLACKLIST: &[&str] = &[
    "cargo", "npm", "yarn", "pnpm", "go", "python", "pip", "git", "rustc", "rustup", "node",
    "deno", "bun", "make", "cmake", "gradle", "mvn", "cat", "ls", "find", "grep", "head", "tail",
    "less", "more", "echo", "printf", "env", "which", "pwd", "cd",
];

/// Maximum number of auto-learned deny rules to prevent unbounded growth.
const MAX_AUTO_BLACKLIST_ENTRIES: usize = 50;

/// Shell interpreters and execution commands that should never be auto-whitelisted.
/// These allow arbitrary code execution and could be used to bypass security controls.
const SHELL_EXEC_COMMANDS: &[&str] = &["bash", "sh", "zsh", "eval", "exec", "source"];

/// Check whether a command pattern is too broad or structurally dangerous
/// for auto-whitelisting.
///
/// Rejects commands containing:
/// - Command chaining operators: `|`, `&&`, `||`, `;`
/// - Shell execution commands: `bash`, `sh`, `zsh`, `eval`, `exec`, `source`
/// - Output redirection: `>`, `>>`
/// - Subshell/substitution syntax: `$(`, `` ` ``, `<(`, `>(`
/// - Overly broad wildcards: command is just `*` or starts with `*`
pub(crate) fn is_pattern_too_broad(command: &str) -> bool {
    let trimmed = command.trim();

    // Reject empty or overly broad wildcard patterns
    if trimmed.is_empty() || trimmed == "*" || trimmed.starts_with("* ") {
        return true;
    }

    // Check for command chaining operators
    if trimmed.contains('|')
        || trimmed.contains("&&")
        || trimmed.contains("||")
        || trimmed.contains(';')
    {
        return true;
    }

    // Check for output redirection (> or >>)
    // We check for '>' but must not flag '->' or '=>' which are common in code output
    // Simple approach: any standalone '>' or '>>' is suspicious in a shell command
    if trimmed.contains(">>") {
        return true;
    }
    // Check for '>' that is not part of '>>' (already checked), '->', or '=>'
    // Also exclude '>(' which is checked separately below
    for (i, ch) in trimmed.char_indices() {
        if ch == '>' {
            // Already caught '>>' above. Check this '>' is not preceded by '-', '=',
            // and not followed by '(' (process substitution, checked separately).
            let prev = if i > 0 {
                trimmed.as_bytes().get(i - 1).copied()
            } else {
                None
            };
            let next = trimmed.as_bytes().get(i + 1).copied();
            if prev != Some(b'-') && prev != Some(b'=') && next != Some(b'(') && next != Some(b'>')
            {
                return true;
            }
        }
    }

    // Check for subshell/substitution syntax
    if trimmed.contains("$(")
        || trimmed.contains('`')
        || trimmed.contains("<(")
        || trimmed.contains(">(")
    {
        return true;
    }

    // Check for shell execution commands anywhere in the command tokens
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    for token in &tokens {
        if SHELL_EXEC_COMMANDS.contains(token) {
            return true;
        }
    }

    false
}

/// Track user decision for potential auto-learning
pub(crate) fn track_user_decision(
    storage: &Storage,
    command: &str,
    project_path: &str,
    approved: bool,
) {
    // Load config for learning thresholds
    let config = Config::load().unwrap_or_default();

    if !config.user_learning.enabled {
        return;
    }

    // Extract command pattern (first word + any subcommand)
    let pattern = extract_command_pattern(command);

    // Check if a rule already exists for this pattern
    if let Ok(Some(mut rule)) = storage.get_rule_by_pattern(&pattern) {
        if approved {
            rule.confirmation_count += 1;

            // Check if we should auto-whitelist
            if rule.confirmation_count >= config.user_learning.auto_whitelist_threshold as i32 {
                if is_restricted_command(command) {
                    debug!(
                        "Skipping auto-whitelist for restricted command: {}",
                        pattern
                    );
                } else if is_pattern_too_broad(command) {
                    debug!(
                        "Skipping auto-whitelist for structurally dangerous command: {}",
                        pattern
                    );
                } else {
                    rule.rule_type = RuleType::Allow;
                    debug!("Auto-whitelisting pattern: {}", pattern);
                }
            }
        } else {
            rule.denial_count += 1;

            // Check if we should auto-blacklist
            if rule.denial_count >= config.user_learning.auto_blacklist_threshold as i32 {
                let base_cmd = command.split_whitespace().next().unwrap_or("");
                let cmd_name = std::path::Path::new(base_cmd)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(base_cmd);

                if NEVER_AUTO_BLACKLIST.contains(&cmd_name) {
                    debug!(
                        "Skipping auto-blacklist for critical dev command: {}",
                        pattern
                    );
                } else if storage
                    .get_rules()
                    .map(|rules| {
                        rules
                            .iter()
                            .filter(|r| r.rule_type == RuleType::Deny)
                            .count()
                    })
                    .unwrap_or(0)
                    >= MAX_AUTO_BLACKLIST_ENTRIES
                {
                    debug!(
                        "Skipping auto-blacklist: cap of {} deny rules reached",
                        MAX_AUTO_BLACKLIST_ENTRIES
                    );
                } else {
                    rule.rule_type = RuleType::Deny;
                    debug!("Auto-blacklisting pattern: {}", pattern);
                }
            }
        }

        if let Err(e) = storage.add_rule(&rule) {
            warn!("Failed to update rule: {}", e);
        }
    } else {
        // Create new rule tracking
        let mut rule = LearnedRule::new(
            pattern.clone(),
            if approved {
                RuleType::Allow
            } else {
                RuleType::Deny
            },
            "user_decision".to_string(),
        );
        rule.project_path = Some(project_path.to_string());
        rule.confirmation_count = i32::from(approved);
        rule.denial_count = i32::from(!approved);

        if let Err(e) = storage.add_rule(&rule) {
            warn!("Failed to add rule: {}", e);
        }
    }
}

/// Extract a generalizable pattern from a command
pub(crate) fn extract_command_pattern(command: &str) -> String {
    let parts: Vec<&str> = command.split_whitespace().collect();

    if parts.is_empty() {
        return command.to_string();
    }

    // Strip path prefix (e.g., /usr/local/bin/cargo -> cargo)
    let raw_cmd = parts[0];
    let cmd = std::path::Path::new(raw_cmd)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(raw_cmd);

    match cmd {
        "git" | "npm" | "yarn" | "pnpm" | "cargo" | "go" | "python" | "pip" => {
            if parts.len() > 1 {
                format!("Bash({}:{}*)", cmd, parts[1])
            } else {
                format!("Bash({cmd}:*)")
            }
        }
        "rm" | "mv" | "cp" | "chmod" | "chown" => {
            // For file operations, include flags but generalize paths
            if parts.len() > 1 && parts[1].starts_with('-') {
                format!("Bash({}:{} *)", cmd, parts[1])
            } else {
                format!("Bash({cmd}:*)")
            }
        }
        _ => format!("Bash({cmd}:*)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clx_core::storage::Storage;
    use clx_core::types::RuleType;

    // Default thresholds from Config::default(): whitelist=3, blacklist=2.
    // track_user_decision uses Config::load() which falls back to defaults when
    // no config file exists, so tests do not need to write a config file.

    /// T15-1: N-1 approvals (below whitelist threshold) must not produce an Allow rule.
    #[test]
    fn test_below_whitelist_threshold_no_rule_upgrade() {
        // Arrange
        let storage = Storage::open_in_memory().expect("in-memory storage");
        let command = "cargo build";
        let project = "/tmp/project";

        // Act — call (threshold-1) = 2 times with approved=true
        track_user_decision(&storage, command, project, true);
        track_user_decision(&storage, command, project, true);

        // Assert — pattern exists but is still tracking (RuleType::Allow is the initial
        // value assigned on first decision; what must NOT happen is confirmation_count
        // reaching the threshold that would have triggered a debug log and kept Allow).
        // The real invariant is: confirmation_count == 2, below threshold of 3.
        let pattern = extract_command_pattern(command);
        let rule = storage
            .get_rule_by_pattern(&pattern)
            .expect("storage query")
            .expect("rule should exist after decisions");
        assert_eq!(rule.confirmation_count, 2, "should have 2 confirmations");
        // rule_type stays Allow (initial), but confirmation_count < threshold means
        // the auto-whitelist branch was NOT triggered (no log, no mutation to deny)
        assert_eq!(rule.rule_type, RuleType::Allow);
    }

    /// T15-2: Exactly `auto_whitelist_threshold` approvals → rule stays Allow (auto-whitelist).
    #[test]
    fn test_auto_whitelist_at_threshold() {
        // Arrange
        let storage = Storage::open_in_memory().expect("in-memory storage");
        // Use a safe command that is not in NEVER_AUTO_WHITELIST and not too broad
        let command = "cargo test";
        let project = "/tmp/project";

        // Act — call threshold (3) times
        for _ in 0..3 {
            track_user_decision(&storage, command, project, true);
        }

        // Assert
        let pattern = extract_command_pattern(command);
        let rule = storage
            .get_rule_by_pattern(&pattern)
            .expect("storage query")
            .expect("rule should exist");
        assert_eq!(rule.confirmation_count, 3);
        assert_eq!(
            rule.rule_type,
            RuleType::Allow,
            "should be Allow after reaching whitelist threshold"
        );
    }

    /// T15-3: Exactly `auto_blacklist_threshold` denials → rule becomes Deny (auto-blacklist).
    #[test]
    fn test_auto_blacklist_at_threshold() {
        // Arrange
        let storage = Storage::open_in_memory().expect("in-memory storage");
        // Use a command that is NOT in NEVER_AUTO_BLACKLIST
        let command = "curl http://example.com";
        let project = "/tmp/project";

        // Act — call threshold (2) times with approved=false
        for _ in 0..2 {
            track_user_decision(&storage, command, project, false);
        }

        // Assert
        let pattern = extract_command_pattern(command);
        let rule = storage
            .get_rule_by_pattern(&pattern)
            .expect("storage query")
            .expect("rule should exist");
        assert_eq!(rule.denial_count, 2);
        assert_eq!(
            rule.rule_type,
            RuleType::Deny,
            "should be Deny after reaching blacklist threshold"
        );
    }

    /// T15-4: Mixed allow/deny decisions, each count below its threshold → no promotion.
    #[test]
    fn test_mixed_decisions_below_threshold_no_promotion() {
        // Arrange
        let storage = Storage::open_in_memory().expect("in-memory storage");
        let command = "curl http://example.com";
        let project = "/tmp/project";

        // Act — 1 allow then 1 deny (both counts < their respective thresholds)
        track_user_decision(&storage, command, project, true);
        track_user_decision(&storage, command, project, false);

        // Assert
        let pattern = extract_command_pattern(command);
        let rule = storage
            .get_rule_by_pattern(&pattern)
            .expect("storage query")
            .expect("rule should exist");
        // confirmation_count=1 < 3, denial_count=1 < 2 → no promotion to a promoted state
        assert_eq!(rule.confirmation_count, 1);
        assert_eq!(rule.denial_count, 1);
        // Rule type reflects the most recently stored value; importantly it was
        // NOT force-upgraded to Deny (denial_count=1, threshold=2) nor stayed Allow
        // from whitelist promotion (confirmation_count=1, threshold=3).
        // The type cycles with each call; the key assertion is neither threshold was crossed.
        assert!(
            rule.confirmation_count < 3,
            "confirmation_count must be below whitelist threshold"
        );
        assert!(
            rule.denial_count < 2,
            "denial_count must be below blacklist threshold"
        );
    }

    /// T15-5: A second set of decisions for an already-existing rule must not create a duplicate.
    #[test]
    fn test_idempotency_no_duplicate_rule() {
        // Arrange
        let storage = Storage::open_in_memory().expect("in-memory storage");
        let command = "cargo test";
        let project = "/tmp/project";

        // Act — record the same pattern multiple times
        for _ in 0..3 {
            track_user_decision(&storage, command, project, true);
        }
        // Record once more beyond threshold
        track_user_decision(&storage, command, project, true);

        // Assert — only one rule exists for this pattern (ON CONFLICT DO UPDATE)
        let pattern = extract_command_pattern(command);
        let all_rules = storage.get_rules().expect("get_rules");
        let matching: Vec<_> = all_rules.iter().filter(|r| r.pattern == pattern).collect();
        assert_eq!(
            matching.len(),
            1,
            "should have exactly one rule for the pattern, not a duplicate"
        );
    }
}

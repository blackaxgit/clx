//! Command validation policies for CLX (Layer 0 + Layer 1)
//!
//! This module provides two-tiered command validation:
//!
//! ## Layer 0 - Deterministic Rules (~1-5ms)
//! Fast, pattern-based validation using whitelist/blacklist matching.
//! This is the "fast path" for known command patterns.
//!
//! ## Layer 1 - LLM-Based Validation (~100-500ms)
//! Uses Ollama LLM to assess risk of unknown commands. Only invoked when
//! Layer 0 returns Ask (command not in whitelist or blacklist).
//!
//! Pattern syntax (canonical `ToolName(command:args)` form, host-neutral):
//! - `Bash(git:*)` - matches all git commands
//! - `Bash(npm:test*)` - matches npm test, npm test:unit, etc.
//! - `Bash(rm:-rf /*)` - matches rm -rf from root
//! - `Bash(curl:*|bash)` - matches curl pipe to bash
//! - `*` matches any sequence of characters

pub mod cache;
mod file_util;
mod llm;
pub mod matching;
pub mod mcp;
pub mod prompts;
mod rate_limiter;
pub mod read_only;
mod rules;
mod traits;
pub mod types;

pub use traits::PolicyEvaluator;

pub use cache::{ValidationCache, compute_cache_key};
pub use file_util::ensure_default_rules_file;
pub use llm::{DEFAULT_VALIDATOR_PROMPT, load_validator_prompt};
pub use matching::{glob_match, is_overbroad_allow_pattern};
pub use mcp::{McpExtraction, extract_mcp_command};
pub use prompts::{PROMPT_HIGH, PROMPT_LOW, PROMPT_STANDARD};
pub use read_only::is_read_only_command;
pub use types::*;

use matching::parse_pattern;
use rate_limiter::RateLimiter;
use read_only::split_segments_quote_aware;

use tracing::debug;

/// Policy engine for deterministic command validation (Layer 0)
///
/// Thread-safe and designed for fast evaluation (~1-5ms).
#[derive(Debug)]
pub struct PolicyEngine {
    /// Whitelist rules (checked after blacklist)
    whitelist: Vec<PolicyRule>,

    /// Blacklist rules (checked first)
    blacklist: Vec<PolicyRule>,

    /// Graylist rules (hidden/internal builtin-only `Ask` tier, Issue 3).
    ///
    /// Checked after the blacklist and before the whitelist. These rules are
    /// NEVER loaded from or written to the learned-rules DB — they are populated
    /// only by `load_builtin_rules`, so a graylist verdict can never be learned
    /// or persisted.
    graylist: Vec<PolicyRule>,

    /// Current project path (for filtering project-specific rules)
    project_path: Option<String>,

    /// Rate limiter for LLM calls
    rate_limiter: RateLimiter,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    /// Create a new policy engine with default built-in rules
    #[must_use]
    pub fn new() -> Self {
        let mut engine = Self {
            whitelist: Vec::new(),
            blacklist: Vec::new(),
            graylist: Vec::new(),
            project_path: None,
            rate_limiter: RateLimiter::new(30),
        };
        engine.load_builtin_rules();
        engine
    }

    /// Create a policy engine with no rules
    #[must_use]
    pub fn empty() -> Self {
        Self {
            whitelist: Vec::new(),
            blacklist: Vec::new(),
            graylist: Vec::new(),
            project_path: None,
            rate_limiter: RateLimiter::new(30),
        }
    }

    /// Set the current project path for filtering project-specific rules
    #[must_use]
    pub fn with_project_path(mut self, project_path: impl Into<String>) -> Self {
        self.project_path = Some(project_path.into());
        self
    }

    /// Add a whitelist rule
    pub fn add_whitelist(&mut self, pattern: impl Into<String>) {
        self.whitelist.push(PolicyRule::whitelist(pattern.into()));
    }

    /// Add a blacklist rule
    pub fn add_blacklist(&mut self, pattern: impl Into<String>) {
        self.blacklist.push(PolicyRule::blacklist(pattern.into()));
    }

    /// Get all whitelist rules
    pub fn whitelist_rules(&self) -> &[PolicyRule] {
        &self.whitelist
    }

    /// Get all blacklist rules
    pub fn blacklist_rules(&self) -> &[PolicyRule] {
        &self.blacklist
    }

    /// Get all graylist rules (hidden/internal builtin-only `Ask` tier).
    pub fn graylist_rules(&self) -> &[PolicyRule] {
        &self.graylist
    }

    /// Evaluate a command against policies (Issue 3 — ASYMMETRIC compound
    /// matching).
    ///
    /// Evaluation order is blacklist → graylist → whitelist → fallthrough Ask,
    /// but compound (multi-segment) handling is deliberately asymmetric so that
    /// a single dangerous segment can never be "hidden" behind a safe one:
    ///
    /// 1. **Deny (blacklist):** deny if the WHOLE command matches a blacklist
    ///    rule OR if ANY individual segment matches a blacklist rule. So
    ///    `ls && rm -rf /` denies on the `rm -rf /` segment, and
    ///    `git diff && rm -rf /` denies on segment 2 (it is NOT allowed just
    ///    because `git diff` is whitelisted).
    /// 2. **Ask (graylist):** after the deny check, return Ask if — splitting
    ///    into segments and stripping a single leading literal `cd <one-token>`
    ///    segment — ANY remaining segment matches a graylist rule.
    /// 3. **Allow (whitelist):** allow ONLY if, after the same split + cd-strip,
    ///    EVERY remaining segment individually matches a whitelist rule. Never
    ///    "allow if any segment".
    /// 4. **Fallthrough:** Ask (unknown command, needs Layer 1).
    pub fn evaluate(&self, tool_name: &str, command: &str) -> PolicyDecision {
        // Split into segments once (quote-aware). On unbalanced quotes the
        // splitter returns None; we then fall back to treating the whole
        // command as a single segment (the whole-command checks below still
        // apply, and an unparseable command fails through to Ask).
        let segments = split_segments_quote_aware(command).unwrap_or_default();

        // 1. DENY — whole command OR any segment matches a blacklist rule.
        for rule in &self.blacklist {
            let matched_whole = self.matches_rule(tool_name, command, rule);
            let matched_segment = segments
                .iter()
                .any(|seg| self.matches_rule(tool_name, seg, rule));
            if matched_whole || matched_segment {
                let reason = rule
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("Matched blacklist pattern: {}", rule.pattern));
                debug!(
                    "Blacklist match: command='{}' pattern='{}'",
                    command, rule.pattern
                );
                return PolicyDecision::Deny { reason };
            }
        }

        // Segments to consider for graylist/whitelist matching: drop a single
        // leading literal `cd <one-token>` segment so that `cd /repo && git diff`
        // is judged on `git diff` alone.
        let effective: Vec<&str> = strip_leading_cd(&segments);

        // 2. ASK — any effective segment matches a graylist rule (after the deny
        //    check has already ruled out a blacklist hit).
        for rule in &self.graylist {
            let matched_whole = self.matches_rule(tool_name, command, rule);
            let matched_segment = effective
                .iter()
                .any(|seg| self.matches_rule(tool_name, seg, rule));
            if matched_whole || matched_segment {
                let reason = rule
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("Matched graylist pattern: {}", rule.pattern));
                debug!(
                    "Graylist match: command='{}' pattern='{}'",
                    command, rule.pattern
                );
                return PolicyDecision::Ask { reason };
            }
        }

        // 3. ALLOW — every effective segment must individually match a whitelist
        //    rule. A single non-whitelisted segment => not allowed.
        if !effective.is_empty()
            && effective
                .iter()
                .all(|seg| self.matches_any_whitelist(tool_name, seg))
        {
            debug!("Whitelist match (all segments): command='{}'", command);
            return PolicyDecision::Allow;
        }

        // 4. Unknown command - needs Layer 1 evaluation.
        PolicyDecision::Ask {
            reason: "Unknown command, requires review".to_string(),
        }
    }

    /// True if `segment` matches any whitelist rule for `tool_name`.
    fn matches_any_whitelist(&self, tool_name: &str, segment: &str) -> bool {
        self.whitelist
            .iter()
            .any(|rule| self.matches_rule(tool_name, segment, rule))
    }

    /// Check if a command matches a rule pattern
    fn matches_rule(&self, tool_name: &str, command: &str, rule: &PolicyRule) -> bool {
        // Check project path filter
        if let Some(ref rule_project) = rule.project_path {
            if let Some(ref current_project) = self.project_path {
                if rule_project != current_project {
                    return false;
                }
            } else {
                return false;
            }
        }

        let pattern = &rule.pattern;

        // Pattern format: ToolName(command_pattern)
        if let Some((pattern_tool, command_pattern)) = parse_pattern(pattern) {
            if pattern_tool != tool_name {
                return false;
            }
            glob_match(&command_pattern, command)
        } else {
            // Fallback: treat as simple command pattern
            glob_match(pattern, command)
        }
    }
}

/// Strip a single leading literal `cd <one-token>` segment from `segments`,
/// returning the remaining segments as string slices (Issue 3).
///
/// The strip applies ONLY when the first segment is exactly `cd` followed by
/// exactly ONE token that contains no shell metacharacters. So `cd /repo` is
/// stripped, but `cd $(evil)`, `cd a b` (two tokens), and a bare `cd` are NOT
/// stripped (they are kept so the dangerous/ambiguous form is still evaluated).
fn strip_leading_cd(segments: &[String]) -> Vec<&str> {
    if let Some((first, rest)) = segments.split_first()
        && is_simple_cd_segment(first)
        && !rest.is_empty()
    {
        return rest.iter().map(String::as_str).collect();
    }
    segments.iter().map(String::as_str).collect()
}

/// True if `segment` is a literal `cd` followed by exactly one metachar-free
/// token (e.g. `cd /repo`, `cd src`). `cd`, `cd a b`, and `cd $(x)` are not.
fn is_simple_cd_segment(segment: &str) -> bool {
    let trimmed = segment.trim();
    let Some(arg) = trimmed.strip_prefix("cd ") else {
        return false;
    };
    let arg = arg.trim();
    if arg.is_empty() {
        return false;
    }
    // Exactly one token: no internal whitespace.
    if arg.split_whitespace().count() != 1 {
        return false;
    }
    // No shell metacharacters that could smuggle execution or expansion.
    const METACHARS: &[char] = &[
        '$', '`', '(', ')', '<', '>', '|', '&', ';', '*', '?', '{', '}', '[', ']', '~', '!', '\\',
        '"', '\'',
    ];
    !arg.contains(METACHARS)
}

#[cfg(test)]
mod tests;

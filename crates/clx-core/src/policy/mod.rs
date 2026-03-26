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
//! Pattern syntax (Claude Code style):
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
pub use matching::glob_match;
pub use mcp::{McpExtraction, extract_mcp_command};
pub use prompts::{PROMPT_HIGH, PROMPT_LOW, PROMPT_STANDARD};
pub use read_only::is_read_only_command;
pub use types::*;

use matching::parse_pattern;
use rate_limiter::RateLimiter;

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

    /// Evaluate a command against policies
    ///
    /// Evaluation order:
    /// 1. Check blacklist rules (deny if matched)
    /// 2. Check whitelist rules (allow if matched)
    /// 3. Return Ask (unknown command, needs L1 evaluation)
    ///
    /// Returns the decision and optionally the matching rule.
    pub fn evaluate(&self, tool_name: &str, command: &str) -> PolicyDecision {
        // Check blacklist first (deny takes priority)
        for rule in &self.blacklist {
            if self.matches_rule(tool_name, command, rule) {
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

        // Check whitelist (allow if matched)
        for rule in &self.whitelist {
            if self.matches_rule(tool_name, command, rule) {
                debug!(
                    "Whitelist match: command='{}' pattern='{}'",
                    command, rule.pattern
                );
                return PolicyDecision::Allow;
            }
        }

        // Unknown command - needs Layer 1 evaluation
        PolicyDecision::Ask {
            reason: "Unknown command, requires review".to_string(),
        }
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

#[cfg(test)]
mod tests;

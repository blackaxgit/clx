//! Policy-specific types: decisions, rules, and configuration.

use serde::{Deserialize, Serialize};

/// Response from LLM validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmValidationResponse {
    /// Risk score from 1-10
    pub risk_score: u8,

    /// Brief explanation of the risk assessment
    pub reasoning: String,

    /// Risk category
    pub category: String,
}

/// Result of policy evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// Command is allowed (bypass permission dialog)
    Allow,

    /// Command is blocked with reason (sent to Claude as error)
    Deny { reason: String },

    /// Command requires user confirmation (show Claude Code's permission dialog)
    Ask { reason: String },
}

impl PolicyDecision {
    /// Convert to Claude Code's permissionDecision format.
    ///
    /// Historical Claude wire format: `allow` / `deny` / `ask`. This method
    /// and its ~9 callers (with hardcoded string assertions) are left
    /// unchanged; v0.10.0 adds the host-aware variants below additively
    /// (gap-scan gap #3, comprehensive-plan REVIEW FIX #3).
    #[must_use]
    pub fn to_permission_decision(&self) -> &'static str {
        match self {
            PolicyDecision::Allow => "allow",
            PolicyDecision::Deny { .. } => "deny",
            PolicyDecision::Ask { .. } => "ask",
        }
    }

    /// Convert to the Codex CLI permission-decision format.
    ///
    /// Codex 0.135.0 hooks support only `allow` / `deny` (P0 finding F1):
    /// there is no interactive `ask`. CLX maps an `ask` verdict to a
    /// fail-closed `deny` so an unconfirmed command is blocked rather than
    /// silently allowed. `allow` and `deny` pass through unchanged.
    #[must_use]
    pub fn to_codex_format(&self) -> &'static str {
        match self {
            PolicyDecision::Allow => "allow",
            // ask -> deny (fail closed): Codex has no interactive ask.
            PolicyDecision::Deny { .. } | PolicyDecision::Ask { .. } => "deny",
        }
    }

    /// Convert to Cursor's flat `permission` field format.
    ///
    /// Cursor supports interactive `ask` (unlike Codex), so the three-valued
    /// verdict maps directly to `allow` / `deny` / `ask` (P0 finding F7).
    #[must_use]
    pub fn to_cursor_format(&self) -> &'static str {
        match self {
            PolicyDecision::Allow => "allow",
            PolicyDecision::Deny { .. } => "deny",
            PolicyDecision::Ask { .. } => "ask",
        }
    }

    /// Get the reason for the decision (if any)
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            PolicyDecision::Allow => None,
            PolicyDecision::Deny { reason } => Some(reason),
            PolicyDecision::Ask { reason } => Some(reason),
        }
    }
}

/// Type of policy rule
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyRuleType {
    /// Whitelist rule - command is allowed
    Whitelist,
    /// Blacklist rule - command is blocked
    Blacklist,
}

/// Source of a policy rule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSource {
    /// Built-in default rules
    Builtin,
    /// Loaded from YAML configuration file
    Config,
    /// Learned from user decisions (stored in database)
    Learned,
    /// Manually added via CLI
    Manual,
}

/// A policy rule for command validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// The pattern to match (Claude Code style)
    pub pattern: String,

    /// Type of rule (whitelist or blacklist)
    pub rule_type: PolicyRuleType,

    /// Source of the rule
    pub source: RuleSource,

    /// Optional description of the rule
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Project path this rule applies to (None for global)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_path: Option<String>,
}

impl PolicyRule {
    /// Create a new whitelist rule
    pub fn whitelist(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            rule_type: PolicyRuleType::Whitelist,
            source: RuleSource::Builtin,
            description: None,
            project_path: None,
        }
    }

    /// Create a new blacklist rule
    pub fn blacklist(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            rule_type: PolicyRuleType::Blacklist,
            source: RuleSource::Builtin,
            description: None,
            project_path: None,
        }
    }

    /// Set the source of the rule
    #[must_use]
    pub fn with_source(mut self, source: RuleSource) -> Self {
        self.source = source;
        self
    }

    /// Set the description of the rule
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the project path this rule applies to
    #[must_use]
    pub fn with_project_path(mut self, project_path: impl Into<String>) -> Self {
        self.project_path = Some(project_path.into());
        self
    }
}

/// Rules configuration loaded from YAML
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RulesConfig {
    /// Whitelist patterns
    #[serde(default)]
    pub whitelist: Vec<String>,

    /// Blacklist patterns
    #[serde(default)]
    pub blacklist: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::PolicyDecision;

    #[test]
    fn claude_format_is_unchanged_three_valued() {
        // Pins the historical Claude wire strings (additive-only obligation).
        assert_eq!(PolicyDecision::Allow.to_permission_decision(), "allow");
        assert_eq!(
            PolicyDecision::Deny { reason: "x".into() }.to_permission_decision(),
            "deny"
        );
        assert_eq!(
            PolicyDecision::Ask { reason: "x".into() }.to_permission_decision(),
            "ask"
        );
    }

    #[test]
    fn codex_format_maps_ask_to_fail_closed_deny() {
        // P0 F1: Codex has no interactive ask -> ask becomes deny.
        assert_eq!(PolicyDecision::Allow.to_codex_format(), "allow");
        assert_eq!(
            PolicyDecision::Deny { reason: "x".into() }.to_codex_format(),
            "deny"
        );
        assert_eq!(
            PolicyDecision::Ask { reason: "x".into() }.to_codex_format(),
            "deny"
        );
    }

    #[test]
    fn cursor_format_preserves_ask() {
        // P0 F7: Cursor supports interactive ask via the flat permission field.
        assert_eq!(PolicyDecision::Allow.to_cursor_format(), "allow");
        assert_eq!(
            PolicyDecision::Deny { reason: "x".into() }.to_cursor_format(),
            "deny"
        );
        assert_eq!(
            PolicyDecision::Ask { reason: "x".into() }.to_cursor_format(),
            "ask"
        );
    }
}

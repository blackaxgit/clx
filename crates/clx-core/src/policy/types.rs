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
    /// Convert to Claude Code's permissionDecision format
    #[must_use]
    pub fn to_permission_decision(&self) -> &'static str {
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

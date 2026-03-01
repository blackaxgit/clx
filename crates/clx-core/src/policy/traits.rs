//! Trait abstraction for policy evaluation.
//!
//! `PolicyEvaluator` provides a minimal trait for Layer 0 deterministic
//! command validation. The concrete implementation is [`super::PolicyEngine`].
//!
//! This trait enables:
//! - Mock implementations for unit testing without rule configuration
//! - Future alternative policy backends (e.g., remote policy service)

use super::types::PolicyDecision;

/// Trait for policy evaluation (Layer 0).
///
/// Evaluate a tool command against policy rules and return a decision.
/// The concrete implementation is `PolicyEngine`.
pub trait PolicyEvaluator {
    /// Evaluate a tool command against policy rules.
    ///
    /// Returns [`PolicyDecision::Allow`], [`PolicyDecision::Deny`], or
    /// [`PolicyDecision::Ask`] depending on whether the command matches
    /// whitelist rules, blacklist rules, or is unknown.
    fn evaluate(&self, tool_name: &str, command: &str) -> PolicyDecision;
}

impl PolicyEvaluator for super::PolicyEngine {
    fn evaluate(&self, tool_name: &str, command: &str) -> PolicyDecision {
        self.evaluate(tool_name, command)
    }
}

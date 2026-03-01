//! Output formatting functions for hook responses.

use crate::types::{HookGenericOutput, HookGenericSpecificOutput, HookOutput, HookSpecificOutput};
use tracing::error;

/// Concise rule reminder injected via additionalContext (~100 tokens)
pub(crate) const RULES_REMINDER: &str = "RULES: Delegate via Task tool. Check agent descriptions before selecting. Maximize parallelization. Use clx_recall for past context, clx_rules if stale.";

/// Output a permission decision to stdout as JSON
pub(crate) fn output_decision(
    decision: &str,
    reason: Option<String>,
    additional_context: Option<&str>,
    system_message: Option<&str>,
) {
    let output = HookOutput {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse".to_string(),
            permission_decision: decision.to_string(),
            permission_decision_reason: reason,
            additional_context: additional_context.map(std::string::ToString::to_string),
        },
        system_message: system_message.map(std::string::ToString::to_string),
    };

    match serde_json::to_string(&output) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            error!("JSON serialization error: {}", e);
            println!(
                r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"allow"}}}}"#
            );
        }
    }
}

/// Output a generic hook response to stdout as JSON (no permission decision)
pub(crate) fn output_generic(
    hook_event_name: &str,
    additional_context: Option<&str>,
    system_message: Option<&str>,
) {
    let output = HookGenericOutput {
        hook_specific_output: HookGenericSpecificOutput {
            hook_event_name: hook_event_name.to_string(),
            additional_context: additional_context.map(std::string::ToString::to_string),
        },
        system_message: system_message.map(std::string::ToString::to_string),
    };

    match serde_json::to_string(&output) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            error!("JSON serialization error for {}: {}", hook_event_name, e);
        }
    }
}

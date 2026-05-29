//! Output formatting functions for hook responses.
//!
//! These free functions write the hook response to the process stdout. In
//! v0.10.0 the serialization is owned by the per-host `Host::write_decision`
//! / `Host::write_generic` methods; these wrappers delegate to a host
//! instance and use `std::io::stdout()` as the sink. For the default
//! `ClaudeHost` the emitted bytes are identical to the pre-refactor
//! `println!` form (`{json}\n`), so existing snapshot/contract tests stay
//! green.

use std::io::Write;

use clx_core::policy::PolicyDecision;
use tracing::error;

use crate::host::{ClaudeHost, Host};

/// Concise rule reminder injected via additionalContext (~100 tokens)
pub(crate) const RULES_REMINDER: &str = "RULES: Delegate via Task tool. Check agent descriptions before selecting. Maximize parallelization. Use clx_recall for past context, clx_rules if stale.";

/// Map a legacy decision string + reason to a `PolicyDecision` so the output
/// can be routed through the host. Returns `None` for unknown decision
/// strings (the serialization-error fail-open path handles those).
fn decision_from_parts(decision: &str, reason: Option<String>) -> Option<PolicyDecision> {
    match decision {
        "allow" => Some(PolicyDecision::Allow),
        "deny" => Some(PolicyDecision::Deny {
            reason: reason.unwrap_or_default(),
        }),
        "ask" => Some(PolicyDecision::Ask {
            reason: reason.unwrap_or_default(),
        }),
        _ => None,
    }
}

/// Output a permission decision to stdout as JSON.
///
/// Delegates serialization to the default host (`ClaudeHost`). Behaviour is
/// byte-identical to the pre-refactor `println!` path.
pub(crate) fn output_decision(
    decision: &str,
    reason: Option<String>,
    additional_context: Option<&str>,
    system_message: Option<&str>,
) {
    output_decision_for(
        &ClaudeHost,
        decision,
        reason,
        additional_context,
        system_message,
    );
}

/// Host-routed permission-decision output. The default-host path is exercised
/// by `output_decision`; this form lets host-aware callers (P4) emit through
/// any `&dyn Host`.
pub(crate) fn output_decision_for(
    host: &dyn Host,
    decision: &str,
    reason: Option<String>,
    additional_context: Option<&str>,
    system_message: Option<&str>,
) {
    let Some(policy_decision) = decision_from_parts(decision, reason) else {
        // Unknown decision string: preserve the historical fail-open
        // allow-fallback byte sequence exactly.
        error!("Unknown decision string: {decision}");
        println!(
            r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"allow"}}}}"#
        );
        return;
    };

    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    if let Err(e) = host.write_decision(
        &mut lock,
        "PreToolUse",
        &policy_decision,
        additional_context,
        system_message,
    ) {
        error!("JSON serialization error: {e}");
        let _ = writeln!(
            lock,
            r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"allow"}}}}"#
        );
    }
}

/// Output a generic hook response to stdout as JSON (no permission decision).
///
/// Delegates serialization to the default host (`ClaudeHost`). Byte-identical
/// to the pre-refactor path.
pub(crate) fn output_generic(
    hook_event_name: &str,
    additional_context: Option<&str>,
    system_message: Option<&str>,
) {
    output_generic_for(
        &ClaudeHost,
        hook_event_name,
        additional_context,
        system_message,
    );
}

/// Host-routed generic output.
pub(crate) fn output_generic_for(
    host: &dyn Host,
    hook_event_name: &str,
    additional_context: Option<&str>,
    system_message: Option<&str>,
) {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    if let Err(e) = host.write_generic(
        &mut lock,
        hook_event_name,
        additional_context,
        system_message,
    ) {
        error!("JSON serialization error for {hook_event_name}: {e}");
    }
}

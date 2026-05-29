//! `PermissionRequest` hook handler (Codex-only, P4).
//!
//! Per P0 finding F1, Codex 0.135.0 does NOT support an interactive `ask` from
//! hooks, so the plan's "deny-in-PreToolUse-then-decide-in-PermissionRequest"
//! design is moot. `PermissionRequest` is therefore registered (D5) but is
//! *informational* today: CLX acts as the permission engine and returns a
//! DEFINITIVE allow/deny derived from L0 (deterministic ruleset). There is no
//! `ask` channel here - an unresolved verdict fails closed to `deny`.
//!
//! The handler intentionally runs only the deterministic L0 layer (no LLM
//! round-trip): a `PermissionRequest` is a synchronous gate where a slow or
//! unavailable L1 would stall the host, and the fail-closed posture already
//! covers the "L0 could not clear it" case. This mirrors the security
//! invariant that a command CLX cannot positively clear is never auto-allowed.

use anyhow::Result;
use clx_core::config::Config;
use clx_core::policy::{PolicyDecision, is_read_only_command};
use clx_core::types::AuditDecision;
use tracing::debug;

use crate::audit::log_audit_entry;
use crate::embedding::resolve_command_paths;
use crate::hooks::pre_tool_use::build_trust_gated_engine;
use crate::host::Host;
use crate::output::{RULES_REMINDER, output_decision_for};
use crate::types::HostNeutralInput;

/// Reason surfaced when CLX cannot positively clear a command at L0 and so
/// fails closed. Kept verbatim so the response is stable and greppable.
const PERMISSION_FAILCLOSED_REASON: &str =
    "CLX could not positively clear this command; denying (fail closed). Re-run if intended.";

/// Handle a Codex `PermissionRequest` - return a definitive allow/deny.
///
/// L0 evaluation only: `Allow` -> allow; `Deny` -> deny; `Ask` (unknown to the
/// deterministic ruleset) -> deny (fail closed). Read-only commands that L0
/// leaves unknown are allowed, matching the `PreToolUse` read-only ergonomics.
pub(crate) async fn handle_permission_request(
    input: HostNeutralInput,
    host: &dyn Host,
) -> Result<()> {
    let raw_tool_name = input.tool_name.as_deref().unwrap_or("Unknown");
    let tool_name = host.canonical_tool_name(raw_tool_name);

    let config = Config::load().unwrap_or_default();

    // Resolve the command to evaluate: a top-level `direct_command` (Cursor-
    // style, defensive) wins; otherwise `tool_input.command` for Bash.
    let command_raw = input.direct_command.clone().unwrap_or_else(|| {
        if tool_name == "Bash" {
            input
                .tool_input
                .as_ref()
                .and_then(|v| v.get("command"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        } else {
            String::new()
        }
    });

    // No command to gate (non-command tool): allow. A PermissionRequest for a
    // non-command tool carries no shell risk surface for CLX to evaluate.
    if command_raw.is_empty() {
        debug!("PermissionRequest: no command to evaluate; allowing");
        output_decision_for(host, "allow", None, Some(RULES_REMINDER), None);
        return Ok(());
    }

    // Validator disabled -> allow (parity with PreToolUse).
    if !config.validator.enabled {
        output_decision_for(host, "allow", None, Some(RULES_REMINDER), None);
        return Ok(());
    }

    let resolved = resolve_command_paths(&command_raw);
    let command = resolved.as_str();
    let is_read_only = config.validator.auto_allow_reads && is_read_only_command(command);

    // Trust-gated engine (P6): untrusted / not-seen Codex projects evaluate
    // against global rules only.
    let mut engine = build_trust_gated_engine(host, &input.cwd);
    if config.validator.layer1_enabled
        && let Ok(storage) = clx_core::storage::Storage::open_default()
    {
        let _ = engine.load_learned_rules(&storage);
    }

    // L0 deterministic evaluation. When L0 is disabled there is no
    // deterministic verdict, so anything that is not read-only fails closed.
    let decision = if config.validator.layer0_enabled {
        engine.evaluate("Bash", command)
    } else {
        PolicyDecision::Ask {
            reason: "L0 disabled".to_string(),
        }
    };

    match decision {
        PolicyDecision::Allow => {
            debug!("PermissionRequest L0: allow '{}'", command);
            log_audit_entry(
                &input.session_id,
                command,
                &input.cwd,
                "L0-PERMREQ",
                AuditDecision::Allowed,
                None,
                None,
            );
            output_decision_for(host, "allow", None, Some(RULES_REMINDER), None);
        }
        PolicyDecision::Deny { reason } => {
            debug!("PermissionRequest L0: deny '{}': {}", command, reason);
            log_audit_entry(
                &input.session_id,
                command,
                &input.cwd,
                "L0-PERMREQ",
                AuditDecision::Blocked,
                None,
                Some(&reason),
            );
            output_decision_for(host, "deny", Some(reason), Some(RULES_REMINDER), None);
        }
        PolicyDecision::Ask { .. } => {
            // Read-only unknowns are safe to allow; everything else fails closed
            // (there is no interactive ask channel for a PermissionRequest).
            if is_read_only {
                debug!(
                    "PermissionRequest L0: unknown read-only '{}', allowing",
                    command
                );
                log_audit_entry(
                    &input.session_id,
                    command,
                    &input.cwd,
                    "L0-PERMREQ-READ",
                    AuditDecision::Allowed,
                    None,
                    Some("Read-only command auto-allowed"),
                );
                output_decision_for(host, "allow", None, Some(RULES_REMINDER), None);
            } else {
                debug!(
                    "PermissionRequest L0: unknown '{}', failing closed",
                    command
                );
                log_audit_entry(
                    &input.session_id,
                    command,
                    &input.cwd,
                    "L0-PERMREQ",
                    AuditDecision::Blocked,
                    None,
                    Some(PERMISSION_FAILCLOSED_REASON),
                );
                output_decision_for(
                    host,
                    "deny",
                    Some(PERMISSION_FAILCLOSED_REASON.to_string()),
                    Some(RULES_REMINDER),
                    None,
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::CodexHost;
    use clx_core::policy::PolicyEngine;

    fn permreq_envelope(command: &str) -> HostNeutralInput {
        let raw = serde_json::json!({
            "session_id": "sess-permreq-001",
            "cwd": "/tmp/permreq-proj",
            "hook_event_name": "PermissionRequest",
            "tool_name": "Bash",
            "tool_input": { "command": command }
        })
        .to_string();
        CodexHost
            .parse_hook_input(&raw)
            .expect("parse codex envelope")
    }

    #[test]
    fn envelope_carries_command() {
        let input = permreq_envelope("rm -rf /tmp/x");
        assert_eq!(
            input
                .tool_input
                .as_ref()
                .unwrap()
                .get("command")
                .unwrap()
                .as_str(),
            Some("rm -rf /tmp/x")
        );
    }

    /// L0 definitively denies a destructive command, so `PermissionRequest`
    /// returns a deny (not an ask). Tests the engine verdict the handler maps.
    #[test]
    fn destructive_command_l0_denies() {
        let mut engine = PolicyEngine::new();
        engine.load_default_rules().expect("default rules");
        let decision = engine.evaluate("Bash", "rm -rf /");
        assert!(
            matches!(decision, PolicyDecision::Deny { .. }),
            "rm -rf / must be an L0 deny, got {decision:?}"
        );
    }

    /// An L0-unknown, non-read-only command fails closed to deny (no ask).
    #[test]
    fn unknown_non_readonly_fails_closed() {
        let mut engine = PolicyEngine::new();
        engine.load_default_rules().expect("default rules");
        let decision = engine.evaluate("Bash", "frobnicate --wibble");
        // Unknown to the deterministic ruleset -> Ask, which the handler
        // collapses to a fail-closed deny for a non-read-only command.
        assert!(matches!(decision, PolicyDecision::Ask { .. }));
        assert!(!is_read_only_command("frobnicate --wibble"));
    }

    /// A read-only unknown command is allowed (read-only ergonomics preserved).
    #[test]
    fn unknown_readonly_allowed() {
        assert!(is_read_only_command("ls -la"));
    }
}

//! `PostToolUse` hook handler - log events and track user decisions.

use anyhow::Result;
use clx_core::config::{Config, ContextPressureMode};
use clx_core::policy::{McpExtraction, extract_mcp_command};
use clx_core::redaction::{redact_json_value, redact_secrets};
use clx_core::storage::Storage;
use clx_core::types::{AuditDecision, AuditLogEntry, Event, EventType, ToolEvent, ToolOutcome};
use tracing::{debug, warn};

use crate::hooks::aggregator;
use crate::host::Host;
use crate::learning::{DecisionSource, track_user_decision};
use crate::types::HostNeutralInput;

/// Handle `PostToolUse` hook - log events and track user decisions
pub(crate) async fn handle_post_tool_use(input: HostNeutralInput, host: &dyn Host) -> Result<()> {
    let tool_name = input.tool_name.as_deref().unwrap_or("Unknown");
    let tool_use_id = input.tool_use_id.as_deref().unwrap_or("");

    debug!(
        "PostToolUse: {} (id: {}) in session {}",
        tool_name, tool_use_id, input.session_id
    );

    // Open storage
    let storage = match Storage::open_default() {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to open storage: {}", e);
            return Ok(());
        }
    };

    // Create event record — redact secrets before persisting to SQLite
    let mut event = Event::new(input.session_id.clone(), EventType::ToolUse);
    event.tool_name.clone_from(&input.tool_name);
    event.tool_use_id = Some(tool_use_id.to_string());
    // JSON-aware redaction: walks the Value recursively so that
    // structured secrets like `{"api_key":"plainsecret"}` are scrubbed
    // even when the secret does not appear as `key=value` in the
    // stringified form (Issue 1 from the 0.8.0 Codex audit).
    event.tool_input = input
        .tool_input
        .as_ref()
        .map(|v| redact_json_value(v).to_string());
    event.tool_output = input
        .tool_response
        .as_ref()
        .map(|v| redact_json_value(v).to_string());

    // Store the event
    if let Err(e) = storage.append_event(&event) {
        warn!("Failed to append event: {}", e);
    }

    // Aggregate mutator tools into the tool_events table (60s windowed dedup).
    // Read-only tools (Read, Grep, etc.) are silently skipped. The aggregator
    // is failure-tolerant: any DB or derivation error is logged at warn and
    // does not affect the rest of the hook.
    let tool_input_value = input.tool_input.clone().unwrap_or(serde_json::Value::Null);
    if aggregator::should_aggregate(tool_name, &tool_input_value, host) {
        let outcome = if input.tool_response.is_some() {
            ToolOutcome::Success
        } else {
            ToolOutcome::Error
        };
        let target = aggregator::derive_target(tool_name, &tool_input_value);
        let summary = redacted_summary_for_persistence(tool_name, &tool_input_value, outcome);
        let now_unix = chrono::Utc::now().timestamp();
        let ev = ToolEvent::new(
            input.session_id.clone(),
            tool_name,
            target,
            &summary,
            outcome,
            now_unix,
        );
        if let Err(e) = storage.append_or_extend_tool_event(&ev) {
            warn!("Failed to append tool_event: {}", e);
        }
    }

    // Increment command count for session
    if let Err(e) = storage.increment_command_count(input.session_id.as_str()) {
        warn!("Failed to increment command count: {}", e);
    }

    // Load config once — used for MCP routing and context pressure below
    let config = Config::load().unwrap_or_default();

    // Extract command for learning and audit (Bash or MCP command tools)
    let extracted_command = if tool_name == "Bash" {
        input
            .tool_input
            .as_ref()
            .and_then(|v| v.get("command"))
            .and_then(|v| v.as_str())
            .map(String::from)
    } else if tool_name.starts_with("mcp__") {
        if config.mcp_tools.enabled {
            let tool_input = input.tool_input.clone().unwrap_or(serde_json::Value::Null);
            match extract_mcp_command(tool_name, &tool_input, &config.mcp_tools.command_tools) {
                McpExtraction::Command(cmd) if !cmd.is_empty() => Some(cmd),
                _ => None,
            }
        } else {
            None
        }
    } else {
        None
    };

    // Track user decision for learning (Bash and MCP command tools)
    if let Some(ref command) = extracted_command {
        let was_executed = input.tool_response.is_some();
        if was_executed {
            track_user_decision(&storage, command, &input.cwd, true, DecisionSource::User);
        }
    }

    // Create audit log entry for the execution.
    // SECURITY: redact secrets from the command before persistence; the
    // `pre_tool_use` path uses `log_audit_entry` which wraps redaction,
    // and this path must match. Raw secrets in `audit_log.command` would
    // violate the documented redaction promise.
    if let Some(ref command) = extracted_command {
        let mut entry = AuditLogEntry::new(
            input.session_id.clone(),
            redact_secrets(command),
            "PostToolUse".to_string(),
            AuditDecision::Allowed,
        );
        // R1-J: redact working_dir before persistence, matching the
        // pre_tool_use path (audit.rs). cwd is agent-influenced and can embed
        // inline secrets/tenant paths; storing it raw violated B6-3.
        entry.working_dir = Some(redact_secrets(&input.cwd));

        let host_id = crate::audit::host_id_str(host.host_id());
        if let Err(e) = storage.create_audit_log_with_host(&entry, host_id) {
            warn!("Failed to create audit log: {}", e);
        }
    }

    // --- Context pressure monitoring ---
    if config.context_pressure.mode != ContextPressureMode::Disabled
        && let Some(ref transcript_path) = input.transcript_path
    {
        let (input_tok, output_tok, _) =
            crate::transcript::count_transcript_tokens(transcript_path);
        let total_tokens = input_tok + output_tok;
        let window = config.context_pressure.context_window_size;
        let threshold = (window as f64 * config.context_pressure.threshold) as i64;

        if total_tokens >= threshold {
            let pct = if window > 0 {
                (total_tokens as f64 / window as f64) * 100.0
            } else {
                0.0
            };

            // Auto mode: create snapshot before warning
            if config.context_pressure.mode == ContextPressureMode::Auto {
                use clx_core::types::{Snapshot, SnapshotTrigger};
                let mut snapshot =
                    Snapshot::new(input.session_id.clone(), SnapshotTrigger::ContextPressure);
                snapshot.summary = Some(format!(
                    "Auto-checkpoint at {pct:.0}% context ({total_tokens} tokens)"
                ));
                if let Err(e) = storage.create_snapshot(&snapshot) {
                    warn!("Failed to create context pressure snapshot: {e}");
                } else {
                    debug!("Created context pressure snapshot at {pct:.0}%");
                }
            }

            // Both auto + notify: inject warning via additionalContext
            let warning = format!(
                "WARNING: Context at ~{pct:.0}% capacity ({total_tokens} tokens). Run /compact now to avoid context overflow."
            );
            crate::output::output_generic("PostToolUse", Some(&warning), None);
            return Ok(());
        }
    }

    Ok(())
}

/// Build the redacted summary that is persisted into the `tool_events` row.
///
/// SECURITY: the summary embeds attacker-influenced content (e.g. the raw Bash
/// command string, see [`aggregator::derive_summary`]). It MUST pass through
/// [`redact_secrets`] before persistence so a Bearer token / API key passed as a
/// CLI arg is not written to the local `tool_events` store in clear text. This
/// mirrors the `tool_input` / `tool_output` redaction and the
/// `audit_log.command` redaction in [`handle_post_tool_use`].
///
/// This is the single chokepoint for summary redaction: every persisted
/// `tool_events` summary flows through here, so no other `derive_summary` caller
/// can bypass it (B-PURPLE NO-SHIP #1).
fn redacted_summary_for_persistence(
    tool_name: &str,
    tool_input_value: &serde_json::Value,
    outcome: ToolOutcome,
) -> String {
    redact_secrets(&aggregator::derive_summary(
        tool_name,
        tool_input_value,
        outcome,
    ))
}

#[cfg(test)]
mod summary_redaction_tests {
    //! Regression coverage for B-PURPLE NO-SHIP #1: tool-event summaries were
    //! persisted UNREDACTED, leaking secrets passed as Bash CLI args into the
    //! local `SQLite` `tool_events` store in clear text.
    //!
    //! These tests call the SAME production chokepoint the hook uses
    //! ([`super::redacted_summary_for_persistence`]) and persist the resulting
    //! `ToolEvent` into an in-memory `SQLite` store, then read it back and assert
    //! the synthetic secret is ABSENT. Because the test and the production hook
    //! share that one function, reverting the redaction there fails these tests.
    //! All secrets here are synthetic; no real credential or tenant URL appears.

    use clx_core::storage::Storage;
    use clx_core::types::{SessionId, ToolEvent, ToolOutcome};
    use serde_json::json;

    use super::redacted_summary_for_persistence;
    use crate::hooks::aggregator;

    /// Persist a summary through the real storage path and read it back.
    fn round_trip_summary(command: &str) -> String {
        let storage = Storage::open_in_memory().expect("in-memory store");
        let input = json!({ "command": command });
        // Drive the EXACT production chokepoint (no re-implementation): reverting
        // the redaction inside `redacted_summary_for_persistence` breaks these.
        let summary = redacted_summary_for_persistence("Bash", &input, ToolOutcome::Success);
        let target = aggregator::derive_target("Bash", &json!({ "command": command }));
        let session = SessionId::from("sess-redaction-test");
        let ev = ToolEvent::new(
            session.clone(),
            "Bash",
            target,
            &summary,
            ToolOutcome::Success,
            1_700_000_000,
        );
        storage
            .append_or_extend_tool_event(&ev)
            .expect("persist tool_event");
        let events = storage
            .recent_tool_events_for_session(session.as_str(), 10)
            .expect("read tool_events");
        assert_eq!(events.len(), 1, "exactly one persisted event expected");
        events[0].summary.clone()
    }

    #[test]
    fn bearer_token_in_bash_command_is_redacted_in_persisted_summary() {
        // Synthetic Bearer token passed as a CLI arg to a Bash tool call.
        let secret = "SYNTHvalue12345";
        let cmd = format!("curl -H 'Authorization: Bearer {secret}' https://example.com");
        let persisted = round_trip_summary(&cmd);
        assert!(
            !persisted.contains(secret),
            "Bearer token leaked into persisted tool_event summary: {persisted}"
        );
        assert!(
            persisted.contains("***REDACTED***"),
            "redaction marker must be present: {persisted}"
        );
    }

    #[test]
    fn sk_api_key_in_bash_command_is_redacted_in_persisted_summary() {
        // Synthetic `sk-` style API key.
        let secret = "sk-abcdefghijklmnopqrstuvwxyz1234567890";
        let cmd = format!("git commit -m 'set key {secret}'");
        let persisted = round_trip_summary(&cmd);
        assert!(
            !persisted.contains("abcdefghijklmnopqrstuvwxyz"),
            "sk- API key leaked into persisted tool_event summary: {persisted}"
        );
        assert!(
            persisted.contains("***REDACTED***"),
            "redaction marker must be present: {persisted}"
        );
    }

    #[test]
    fn password_keyword_in_bash_command_is_redacted_in_persisted_summary() {
        // Synthetic `password=...` keyword form.
        let secret = "hunter2synthetic";
        let cmd = format!("rm -rf /tmp/x && mysql --password={secret}");
        let persisted = round_trip_summary(&cmd);
        assert!(
            !persisted.contains(secret),
            "password value leaked into persisted tool_event summary: {persisted}"
        );
        assert!(
            persisted.contains("***REDACTED***"),
            "redaction marker must be present: {persisted}"
        );
    }

    #[test]
    fn benign_bash_summary_is_not_over_redacted() {
        // A mutator Bash command with no secret must pass through verbatim so the
        // fix does not destroy the legitimate summary content.
        let persisted = round_trip_summary("git commit -m 'fix typo'");
        assert!(
            persisted.contains("git commit -m 'fix typo'"),
            "benign command must survive redaction unchanged: {persisted}"
        );
        assert!(
            !persisted.contains("***REDACTED***"),
            "benign command must not be redacted: {persisted}"
        );
    }
}

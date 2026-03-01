//! `PostToolUse` hook handler - log events and track user decisions.

use anyhow::Result;
use clx_core::config::{Config, ContextPressureMode};
use clx_core::policy::{McpExtraction, extract_mcp_command};
use clx_core::redaction::redact_secrets;
use clx_core::storage::Storage;
use clx_core::types::{AuditDecision, AuditLogEntry, Event, EventType};
use tracing::{debug, warn};

use crate::learning::track_user_decision;
use crate::types::HookInput;

/// Handle `PostToolUse` hook - log events and track user decisions
pub(crate) async fn handle_post_tool_use(input: HookInput) -> Result<()> {
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
    event.tool_input = input
        .tool_input
        .as_ref()
        .map(|v| redact_secrets(&v.to_string()));
    event.tool_output = input
        .tool_response
        .as_ref()
        .map(|v| redact_secrets(&v.to_string()));

    // Store the event
    if let Err(e) = storage.append_event(&event) {
        warn!("Failed to append event: {}", e);
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
            track_user_decision(&storage, command, &input.cwd, true);
        }
    }

    // Create audit log entry for the execution
    if let Some(ref command) = extracted_command {
        let mut entry = AuditLogEntry::new(
            input.session_id.clone(),
            command.clone(),
            "PostToolUse".to_string(),
            AuditDecision::Allowed,
        );
        entry.working_dir = Some(input.cwd.clone());

        if let Err(e) = storage.create_audit_log(&entry) {
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

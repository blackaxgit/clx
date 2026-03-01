//! `PreToolUse` hook handler - validate commands before execution.

use anyhow::Result;
use clx_core::config::Config;
use clx_core::ollama::OllamaClient;
use clx_core::policy::{
    McpExtraction, PolicyDecision, PolicyEngine, extract_mcp_command, is_read_only_command,
};
use clx_core::storage::Storage;
use clx_core::types::AuditDecision;
use tracing::{debug, warn};

use crate::audit::log_audit_entry;
use crate::embedding::resolve_command_paths;
use crate::output::{RULES_REMINDER, output_decision};
use crate::types::HookInput;

/// Handle `PreToolUse` hook - validate commands before execution
pub(crate) async fn handle_pre_tool_use(input: HookInput) -> Result<()> {
    let tool_name = input.tool_name.as_deref().unwrap_or("Unknown");

    // Load configuration early (needed for MCP tool routing)
    let config = Config::load().unwrap_or_default();

    // Route by tool type to extract the command to validate.
    // MCP command tools are evaluated through the same PolicyEngine as Bash.
    let command_raw = if tool_name == "Bash" {
        // Bash: extract from tool_input.command
        input
            .tool_input
            .as_ref()
            .and_then(|v| v.get("command"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    } else if tool_name.starts_with("mcp__") && config.mcp_tools.enabled {
        // MCP tool: check if it carries an executable command
        let tool_input = input.tool_input.clone().unwrap_or(serde_json::Value::Null);
        match extract_mcp_command(tool_name, &tool_input, &config.mcp_tools.command_tools) {
            McpExtraction::Command(cmd) => cmd,
            McpExtraction::NotCommandTool => {
                // Not a command-bearing MCP tool — use configured default decision
                let decision = config.mcp_tools.default_decision.as_str();
                output_decision(decision, None, Some(RULES_REMINDER), None);
                return Ok(());
            }
        }
    } else {
        // Non-Bash, non-MCP tools (Read, Write, etc.) → auto-allow
        output_decision("allow", None, Some(RULES_REMINDER), None);
        return Ok(());
    };

    if command_raw.is_empty() {
        output_decision("allow", None, Some(RULES_REMINDER), None);
        return Ok(());
    }

    debug!(
        "PreToolUse: validating [{}] command '{}' in '{}'",
        tool_name, command_raw, input.cwd
    );

    // Skip validation if disabled
    if !config.validator.enabled {
        output_decision("allow", None, Some(RULES_REMINDER), None);
        return Ok(());
    }

    // Trust mode: auto-allow ALL commands (but still log for audit)
    // Trust mode expires after 1 hour via a token file for safety
    if config.validator.trust_mode {
        let trust_token_path = clx_core::paths::clx_dir().join(".trust_mode_token");

        // Atomic check-and-create to avoid TOCTOU race between exists() and write()
        let trust_valid = if let Ok(metadata) = std::fs::metadata(&trust_token_path) {
            // File exists — check if expired (1 hour)
            metadata
                .modified()
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|elapsed| elapsed.as_secs() < 3600)
        } else {
            // File does not exist — create atomically
            let _ = std::fs::create_dir_all(
                trust_token_path
                    .parent()
                    .unwrap_or(std::path::Path::new(".")),
            );
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true) // Atomic: fails if file already exists
                .open(&trust_token_path)
            {
                Ok(mut file) => {
                    use std::io::Write;
                    let _ = file.write_all(b"trust_mode_active");
                    true
                }
                Err(_) => {
                    // Race: another process created it — recheck expiry
                    std::fs::metadata(&trust_token_path)
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .and_then(|modified| modified.elapsed().ok())
                        .is_some_and(|elapsed| elapsed.as_secs() < 3600)
                }
            }
        };

        if trust_valid {
            debug!(
                "Trust mode: auto-allowing [{}] command '{}' (token valid)",
                tool_name, command_raw
            );
            log_audit_entry(
                &input.session_id,
                &command_raw,
                &input.cwd,
                "TRUST",
                AuditDecision::Allowed,
                None,
                Some("Trust mode enabled"),
            );
            output_decision("allow", None, Some(RULES_REMINDER), None);
            return Ok(());
        }

        warn!("Trust mode token expired (>1 hour). Falling back to validation.");
        let _ = std::fs::remove_file(&trust_token_path);
        // Fall through to normal validation
    }

    // Resolve symlinks in command paths for TOCTOU mitigation
    let resolved_command = resolve_command_paths(&command_raw);
    let command = resolved_command.as_str();

    // Check if this is a read-only command (used later to skip confirmation dialog)
    let is_read_only = config.validator.auto_allow_reads && is_read_only_command(command);

    // Initialize policy engine
    let mut policy_engine = PolicyEngine::new().with_project_path(&input.cwd);

    // Load learned rules from database if available
    if let Ok(storage) = Storage::open_default()
        && let Err(e) = policy_engine.load_learned_rules(&storage)
    {
        warn!("Failed to load learned rules: {}", e);
    }

    // Layer 0: Deterministic rules evaluation
    // Always evaluate as "Bash" so all Bash(...) rules apply universally
    // (MCP command tools have their commands extracted and validated identically)
    let l0_decision = policy_engine.evaluate("Bash", command);

    match l0_decision {
        PolicyDecision::Allow => {
            debug!("L0: Allowed command '{}'", command);
            log_audit_entry(
                &input.session_id,
                command,
                &input.cwd,
                "L0",
                AuditDecision::Allowed,
                None,
                None,
            );
            output_decision("allow", None, Some(RULES_REMINDER), None);
            return Ok(());
        }
        PolicyDecision::Deny { reason } => {
            debug!("L0: Denied command '{}': {}", command, reason);
            log_audit_entry(
                &input.session_id,
                command,
                &input.cwd,
                "L0",
                AuditDecision::Blocked,
                None,
                Some(&reason),
            );
            output_decision("deny", Some(reason), Some(RULES_REMINDER), None);
            return Ok(());
        }
        PolicyDecision::Ask { .. } => {
            // For read-only commands: auto-allow without confirmation dialog
            // (L0 didn't explicitly block it, so it's safe)
            if is_read_only {
                debug!("L0: Unknown read-only command '{}', auto-allowing", command);
                log_audit_entry(
                    &input.session_id,
                    command,
                    &input.cwd,
                    "L0-READ",
                    AuditDecision::Allowed,
                    None,
                    Some("Read-only command auto-allowed"),
                );
                output_decision("allow", None, Some(RULES_REMINDER), None);
                return Ok(());
            }
            debug!("L0: Unknown command '{}', checking L1", command);
            // Continue to Layer 1
        }
    }

    // Layer 1: LLM-based validation (if enabled)
    if !config.validator.layer1_enabled {
        debug!("L1 disabled, defaulting to ask");
        log_audit_entry(
            &input.session_id,
            command,
            &input.cwd,
            "L0",
            AuditDecision::Prompted,
            None,
            Some("L1 disabled"),
        );
        output_decision(
            "ask",
            Some("Command requires review".to_string()),
            Some(RULES_REMINDER),
            None,
        );
        return Ok(());
    }

    // Initialize Ollama client for L1 validation
    let ollama = match OllamaClient::new(config.ollama.clone()) {
        Ok(client) => client,
        Err(e) => {
            debug!("Failed to create Ollama client: {}, defaulting to ask", e);
            log_audit_entry(
                &input.session_id,
                command,
                &input.cwd,
                "L1",
                AuditDecision::Prompted,
                None,
                Some(&format!("Ollama client error: {e}")),
            );
            output_decision(
                "ask",
                Some("LLM validation unavailable".to_string()),
                Some(RULES_REMINDER),
                None,
            );
            return Ok(());
        }
    };

    // Check if Ollama is available
    if !ollama.is_available().await {
        debug!("Ollama not available, defaulting to ask");
        log_audit_entry(
            &input.session_id,
            command,
            &input.cwd,
            "L1",
            AuditDecision::Prompted,
            None,
            Some("Ollama unavailable"),
        );
        output_decision(
            "ask",
            Some("LLM validation unavailable".to_string()),
            Some(RULES_REMINDER),
            None,
        );
        return Ok(());
    }

    // Cache is not useful in a short-lived hook process.
    // Each invocation is a separate process, so the cache is always empty.
    let l1_decision = policy_engine
        .evaluate_with_llm("Bash", command, &input.cwd, &ollama, None)
        .await;

    match l1_decision {
        PolicyDecision::Allow => {
            debug!("L1: Allowed command '{}'", command);
            log_audit_entry(
                &input.session_id,
                command,
                &input.cwd,
                "L1",
                AuditDecision::Allowed,
                Some(1),
                None,
            );
            output_decision("allow", None, Some(RULES_REMINDER), None);
        }
        PolicyDecision::Deny { reason } => {
            debug!("L1: Denied command '{}': {}", command, reason);
            log_audit_entry(
                &input.session_id,
                command,
                &input.cwd,
                "L1",
                AuditDecision::Blocked,
                Some(9),
                Some(&reason),
            );
            output_decision("deny", Some(reason), Some(RULES_REMINDER), None);
        }
        PolicyDecision::Ask { reason } => {
            // For read-only commands: auto-allow even if L1 says "ask"
            // (Read-only commands can't cause damage, so no need to confirm)
            if is_read_only {
                debug!(
                    "L1: Ask for read-only command '{}', auto-allowing: {}",
                    command, reason
                );
                log_audit_entry(
                    &input.session_id,
                    command,
                    &input.cwd,
                    "L1-READ",
                    AuditDecision::Allowed,
                    Some(5),
                    Some(&format!("Read-only auto-allowed: {reason}")),
                );
                output_decision("allow", None, Some(RULES_REMINDER), None);
            } else {
                debug!("L1: Ask for command '{}': {}", command, reason);
                log_audit_entry(
                    &input.session_id,
                    command,
                    &input.cwd,
                    "L1",
                    AuditDecision::Prompted,
                    Some(5),
                    Some(&reason),
                );
                output_decision("ask", Some(reason), Some(RULES_REMINDER), None);
            }
        }
    }

    Ok(())
}

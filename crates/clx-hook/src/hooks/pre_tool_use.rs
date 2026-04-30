//! `PreToolUse` hook handler - validate commands before execution.

use anyhow::Result;
use clx_core::config::Config;
use clx_core::config::DefaultDecision;
use clx_core::llm::LocalLlmBackend;
use clx_core::ollama::OllamaClient;
use clx_core::policy::{
    McpExtraction, PolicyDecision, PolicyEngine, compute_cache_key, extract_mcp_command,
    is_read_only_command,
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

    // Trust mode: auto-allow ALL commands via JSON token (but still log for audit)
    if config.validator.trust_mode {
        let trust_token_path = clx_core::paths::clx_dir().join(".trust_mode_token");

        let trust_valid = if let Ok(content) = std::fs::read_to_string(&trust_token_path) {
            // Try JSON token first
            if let Ok(token) = serde_json::from_str::<clx_core::types::TrustToken>(&content) {
                let now = chrono::Utc::now();
                let expires_valid = chrono::DateTime::parse_from_rfc3339(&token.expires_at)
                    .ok()
                    .is_some_and(|exp| now < exp.with_timezone(&chrono::Utc));

                let session_valid = token
                    .session_id
                    .as_ref()
                    .is_none_or(|tok_sid| input.session_id.as_str() == tok_sid);

                if expires_valid && session_valid {
                    let remaining = chrono::DateTime::parse_from_rfc3339(&token.expires_at)
                        .ok()
                        .map(|exp| (exp.with_timezone(&chrono::Utc) - now).num_seconds().max(0));
                    let reason = remaining.map_or_else(
                        || "Trust mode enabled".to_string(),
                        |r| format!("Trust mode ({r}s remaining)"),
                    );
                    debug!(
                        "Trust mode: auto-allowing [{}] command '{}' ({})",
                        tool_name, command_raw, reason
                    );
                    log_audit_entry(
                        &input.session_id,
                        &command_raw,
                        &input.cwd,
                        "TRUST",
                        AuditDecision::Allowed,
                        None,
                        Some(&reason),
                    );
                    output_decision("allow", None, Some(RULES_REMINDER), None);
                    return Ok(());
                }
                // Expired or session mismatch
                false
            } else {
                // Backward compat: old plain-text token — check file mtime
                std::fs::metadata(&trust_token_path)
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|modified| modified.elapsed().ok())
                    .is_some_and(|elapsed| elapsed.as_secs() < 3600)
            }
        } else {
            false
        };

        if trust_valid {
            debug!(
                "Trust mode: auto-allowing [{}] command '{}' (legacy token)",
                tool_name, command_raw
            );
            log_audit_entry(
                &input.session_id,
                &command_raw,
                &input.cwd,
                "TRUST",
                AuditDecision::Allowed,
                None,
                Some("Trust mode enabled (legacy token)"),
            );
            output_decision("allow", None, Some(RULES_REMINDER), None);
            return Ok(());
        }

        warn!("Trust mode token expired or invalid. Falling back to validation.");
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

    // Check SQLite decision cache before calling Ollama
    if config.validator.cache_enabled {
        let cache_key = compute_cache_key(command, &input.cwd);
        if let Ok(storage) = Storage::open_default() {
            // Best-effort cleanup of expired entries (1 in 20 chance)
            if rand_cleanup() {
                let _ = storage.cleanup_expired_cache();
            }

            if let Ok(Some(cached)) = storage.get_cached_decision(&cache_key) {
                debug!("L1-CACHE hit for command: {}", command);
                let audit_decision = match cached.decision.as_str() {
                    "allow" => AuditDecision::Allowed,
                    "deny" => AuditDecision::Blocked,
                    _ => AuditDecision::Prompted,
                };
                log_audit_entry(
                    &input.session_id,
                    command,
                    &input.cwd,
                    "L1-CACHE",
                    audit_decision,
                    cached.risk_score.map(|s| s as i32),
                    cached.reason.as_deref(),
                );
                output_decision(&cached.decision, cached.reason, Some(RULES_REMINDER), None);
                return Ok(());
            }
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
    let ollama = match OllamaClient::new(config.ollama_or_default().clone()) {
        Ok(client) => client,
        Err(e) => {
            debug!(
                "Failed to create Ollama client: {}, defaulting to {}",
                e, config.validator.default_decision
            );
            let fallback = config.validator.default_decision.as_str();
            let reason = format!("LLM unavailable — fallback: {fallback}");
            log_audit_entry(
                &input.session_id,
                command,
                &input.cwd,
                "L1",
                match config.validator.default_decision {
                    DefaultDecision::Allow => AuditDecision::Allowed,
                    DefaultDecision::Deny => AuditDecision::Blocked,
                    DefaultDecision::Ask => AuditDecision::Prompted,
                },
                None,
                Some(&format!(
                    "Ollama client error: {e} — default_decision: {}",
                    config.validator.default_decision
                )),
            );
            output_decision(fallback, Some(reason), Some(RULES_REMINDER), None);
            return Ok(());
        }
    };

    // Check file-based health cache before network call
    let health = clx_core::ollama_health::read_cached_health();
    let ollama_available = match health {
        clx_core::ollama_health::HealthStatus::Available => {
            debug!("Health cache: Ollama recently available, skipping check");
            true
        }
        clx_core::ollama_health::HealthStatus::Unavailable => {
            debug!("Health cache: Ollama recently unavailable, skipping check");
            false
        }
        clx_core::ollama_health::HealthStatus::Unknown => {
            let available = ollama.is_available().await;
            clx_core::ollama_health::write_health(available);
            available
        }
    };

    if !ollama_available {
        debug!(
            "Ollama not available, defaulting to {}",
            config.validator.default_decision
        );
        let fallback = config.validator.default_decision.as_str();
        let reason = format!("LLM unavailable — fallback: {fallback}");
        log_audit_entry(
            &input.session_id,
            command,
            &input.cwd,
            "L1",
            match config.validator.default_decision {
                DefaultDecision::Allow => AuditDecision::Allowed,
                DefaultDecision::Deny => AuditDecision::Blocked,
                DefaultDecision::Ask => AuditDecision::Prompted,
            },
            None,
            Some(&format!(
                "Ollama unavailable — default_decision: {}",
                config.validator.default_decision
            )),
        );
        output_decision(fallback, Some(reason), Some(RULES_REMINDER), None);
        return Ok(());
    }

    // In-memory cache is not useful in a short-lived hook process;
    // SQLite cache (above) handles cross-process caching instead.
    let l1_decision = policy_engine
        .evaluate_with_llm(
            "Bash",
            command,
            &input.cwd,
            &ollama,
            None,
            &config.validator.prompt_sensitivity,
        )
        .await;

    // Handle LLM generation failure: evaluate_with_llm returns Ask("LLM unavailable")
    // when the generation call fails (distinct from the is_available() check above).
    // Apply the same default_decision fallback and update health cache.
    if let PolicyDecision::Ask { ref reason } = l1_decision
        && reason == "LLM unavailable"
    {
        clx_core::ollama_health::write_health(false);
        let fallback = config.validator.default_decision.as_str();
        let fallback_reason = format!("LLM unavailable — fallback: {fallback}");
        log_audit_entry(
            &input.session_id,
            command,
            &input.cwd,
            "L1",
            match config.validator.default_decision {
                DefaultDecision::Allow => AuditDecision::Allowed,
                DefaultDecision::Deny => AuditDecision::Blocked,
                DefaultDecision::Ask => AuditDecision::Prompted,
            },
            None,
            Some(&format!(
                "LLM generation failed — default_decision: {}",
                config.validator.default_decision
            )),
        );
        output_decision(fallback, Some(fallback_reason), Some(RULES_REMINDER), None);
        return Ok(());
    }

    // Update health cache after successful LLM interaction
    clx_core::ollama_health::write_health(true);

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
            // Cache allow decision
            if config.validator.cache_enabled {
                let cache_key = compute_cache_key(command, &input.cwd);
                if let Ok(storage) = Storage::open_default() {
                    let _ = storage.cache_decision(
                        &cache_key,
                        "allow",
                        None,
                        Some(1),
                        config.validator.cache_allow_ttl_secs as i64,
                    );
                }
            }
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
                // Cache the read-only auto-allow as an allow decision
                if config.validator.cache_enabled {
                    let cache_key = compute_cache_key(command, &input.cwd);
                    if let Ok(storage) = Storage::open_default() {
                        let _ = storage.cache_decision(
                            &cache_key,
                            "allow",
                            None,
                            Some(1),
                            config.validator.cache_allow_ttl_secs as i64,
                        );
                    }
                }
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
                // Cache ask decision (before output_decision consumes reason)
                if config.validator.cache_enabled {
                    let cache_key = compute_cache_key(command, &input.cwd);
                    if let Ok(storage) = Storage::open_default() {
                        let _ = storage.cache_decision(
                            &cache_key,
                            "ask",
                            Some(&reason),
                            Some(5),
                            config.validator.cache_ask_ttl_secs as i64,
                        );
                    }
                }
                output_decision("ask", Some(reason), Some(RULES_REMINDER), None);
            }
        }
    }

    Ok(())
}

/// Probabilistic cleanup trigger (~5% of invocations).
fn rand_cleanup() -> bool {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .is_ok_and(|d| d.subsec_nanos() % 20 == 0)
}

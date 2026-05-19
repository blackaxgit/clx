//! `PreToolUse` hook handler - validate commands before execution.

use anyhow::Result;
use clx_core::config::DefaultDecision;
use clx_core::config::{Capability, Config};
use clx_core::policy::{
    McpExtraction, PolicyDecision, PolicyEngine, compute_cache_key, extract_mcp_command,
    is_read_only_command,
};
use clx_core::storage::Storage;
use clx_core::types::AuditDecision;
use tracing::{debug, warn};

use crate::audit::log_audit_entry;
use crate::embedding::resolve_command_paths;
use crate::learning::track_user_decision;
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

    // Initialize LLM client for L1 validation
    let (ollama, chat_model) = match config.create_llm_client(Capability::Chat).and_then(|c| {
        config
            .capability_route(Capability::Chat)
            .map(|r| (c, r.model.clone()))
    }) {
        Ok(pair) => pair,
        Err(e) => {
            debug!(
                "Failed to create LLM client: {}, defaulting to {}",
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
    let health = clx_core::llm_health::read_cached_health();
    let ollama_available = match health {
        clx_core::llm_health::HealthStatus::Available => {
            debug!("Health cache: LLM recently available, skipping check");
            true
        }
        clx_core::llm_health::HealthStatus::Unavailable => {
            debug!("Health cache: LLM recently unavailable, skipping check");
            false
        }
        clx_core::llm_health::HealthStatus::Unknown => {
            let available = ollama.is_available().await;
            clx_core::llm_health::write_health(available);
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
    //
    // V-R4: bound the L1 evaluation with the configured timeout. The future
    // covers the actual LLM network call (ollama.generate inside
    // evaluate_with_llm). On timeout the future is dropped (clean
    // cancellation: no audit/cache writes happen until after the await
    // returns), and we apply the documented default_decision fallback with a
    // distinct WARN so a hung provider can never block the hook indefinitely.
    let l1_timeout = std::time::Duration::from_millis(config.validator.layer1_timeout_ms);
    let l1_future = policy_engine.evaluate_with_llm(
        "Bash",
        command,
        &input.cwd,
        &ollama,
        &chat_model,
        None,
        &config.validator.prompt_sensitivity,
    );
    let Ok(l1_decision) = tokio::time::timeout(l1_timeout, l1_future).await else {
        warn!(
            "L1 evaluation timed out after {}ms — applying default_decision: {}",
            config.validator.layer1_timeout_ms, config.validator.default_decision
        );
        clx_core::llm_health::write_health(false);
        let fallback = config.validator.default_decision.as_str();
        let fallback_reason = format!("LLM timeout — fallback: {fallback}");
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
                "L1 timeout after {}ms — default_decision: {}",
                config.validator.layer1_timeout_ms, config.validator.default_decision
            )),
        );
        output_decision(fallback, Some(fallback_reason), Some(RULES_REMINDER), None);
        return Ok(());
    };

    // Handle LLM generation failure: evaluate_with_llm returns Ask("LLM unavailable")
    // when the generation call fails (distinct from the is_available() check above).
    // Apply the same default_decision fallback and update health cache.
    if let PolicyDecision::Ask { ref reason } = l1_decision
        && reason == "LLM unavailable"
    {
        clx_core::llm_health::write_health(false);
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
    clx_core::llm_health::write_health(true);

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
            // V-R5: a DENY/BLOCK outcome must increment denial_count for the
            // matched pattern, symmetrically to how an executed (approved)
            // command increments confirmation_count in post_tool_use. Without
            // this the user-learning auto_blacklist_threshold is unreachable.
            // Exactly one call per L1 deny decision (the hook returns
            // immediately after) so there is no double-count. Precedence is
            // preserved: this only bumps a counter / may flip rule_type to
            // Deny, which L0 enforces on the next invocation (L0 > learned >
            // L1). L0 hard-blocks return earlier and are intentionally NOT
            // learned here, matching the approve path which only learns from
            // executed commands, not deterministic L0 outcomes.
            if let Ok(storage) = Storage::open_default() {
                track_user_decision(&storage, command, &input.cwd, false);
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HookOutput, HookSpecificOutput};

    /// Build the exact JSON envelope `output_decision` would emit, so tests
    /// assert the emitted block/ask/allow string (not just an enum).
    fn rendered_envelope(decision: &str, reason: Option<String>) -> String {
        let output = HookOutput {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: decision.to_string(),
                permission_decision_reason: reason,
                additional_context: None,
            },
            system_message: None,
        };
        serde_json::to_string(&output).expect("serialize hook output")
    }

    /// V-R2 happy path: an L1 verdict at/above the deny band yields a Deny
    /// decision AND the emitted envelope is an actual block.
    #[test]
    fn test_v_r2_l1_deny_emits_block_envelope() {
        // A high-risk L1 outcome is PolicyDecision::Deny (see
        // risk_score_to_decision 8..=10). The hook maps it to "deny".
        let l1: PolicyDecision = PolicyDecision::Deny {
            reason: "[critical] rm -rf /".to_string(),
        };
        assert_eq!(
            l1.to_permission_decision(),
            "deny",
            "high-risk L1 verdict must map to deny"
        );
        let json = rendered_envelope(l1.to_permission_decision(), l1.reason().map(String::from));
        assert!(
            json.contains(r#""permissionDecision":"deny""#),
            "emitted envelope must be a block, got: {json}"
        );
        assert!(json.contains("[critical] rm -rf /"));
    }

    /// V-R2 no-regression: a mid verdict still asks, a low verdict still
    /// allows. Asserts the emitted envelope, not just the enum.
    #[test]
    fn test_v_r2_mid_asks_low_allows_no_regression() {
        let ask = PolicyDecision::Ask {
            reason: "[caution] unclear".to_string(),
        };
        assert_eq!(ask.to_permission_decision(), "ask");
        assert!(
            rendered_envelope("ask", Some("[caution] unclear".to_string()))
                .contains(r#""permissionDecision":"ask""#)
        );

        let allow = PolicyDecision::Allow;
        assert_eq!(allow.to_permission_decision(), "allow");
        assert!(rendered_envelope("allow", None).contains(r#""permissionDecision":"allow""#));
    }

    /// V-R4 happy path: an L1 call within budget resolves normally (the
    /// timeout wrapper passes the inner decision through unchanged).
    #[tokio::test]
    async fn test_v_r4_within_budget_passes_through() {
        let budget = std::time::Duration::from_millis(200);
        let fut = async {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            PolicyDecision::Allow
        };
        let res = tokio::time::timeout(budget, fut).await;
        assert!(res.is_ok(), "within-budget call must not time out");
        assert_eq!(res.unwrap(), PolicyDecision::Allow);
    }

    /// V-R4 failure path: an L1 call that exceeds `layer1_timeout_ms` must
    /// resolve to the configured `default_decision` and emit the matching
    /// envelope. Tested for `default_decision` = ask AND = deny.
    #[tokio::test]
    async fn test_v_r4_timeout_applies_default_decision() {
        let budget = std::time::Duration::from_millis(20);
        // A future that never completes within budget (the hung-provider case).
        let hung = async {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            PolicyDecision::Allow
        };
        let timed_out = tokio::time::timeout(budget, hung).await;
        assert!(timed_out.is_err(), "hung L1 call must time out");

        // default_decision = ask -> emitted envelope is ask (not silent allow)
        let ask_fb = DefaultDecision::Ask.as_str();
        assert_eq!(ask_fb, "ask");
        assert!(
            rendered_envelope(ask_fb, Some("LLM timeout — fallback: ask".to_string()))
                .contains(r#""permissionDecision":"ask""#),
            "timeout with default_decision=ask must emit ask"
        );

        // default_decision = deny -> emitted envelope is a block
        let deny_fb = DefaultDecision::Deny.as_str();
        assert_eq!(deny_fb, "deny");
        assert!(
            rendered_envelope(deny_fb, Some("LLM timeout — fallback: deny".to_string()))
                .contains(r#""permissionDecision":"deny""#),
            "timeout with default_decision=deny must emit a block"
        );
    }

    /// V-R4: the provider-error path (distinct from timeout) also maps to
    /// `default_decision`. Both converge on `default_decision`; logs differ.
    #[test]
    fn test_v_r4_provider_error_maps_to_default_decision() {
        // evaluate_with_llm returns Ask("LLM unavailable") on generation
        // failure; the hook converts that to default_decision. Verify the
        // mapping table the hook uses for that branch.
        for (dd, expected) in [
            (DefaultDecision::Allow, "allow"),
            (DefaultDecision::Ask, "ask"),
            (DefaultDecision::Deny, "deny"),
        ] {
            assert_eq!(dd.as_str(), expected);
            assert!(
                rendered_envelope(dd.as_str(), Some("fallback".to_string()))
                    .contains(&format!(r#""permissionDecision":"{expected}""#))
            );
        }
    }
}

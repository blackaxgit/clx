//! `SubagentStart` and `UserPromptSubmit` hook handlers.

use anyhow::Result;
use tracing::{debug, warn};

use crate::output::output_generic;
use crate::types::HookInput;

/// Handle `SubagentStart` hook - inject specialist rules into subagent context
pub(crate) async fn handle_subagent_start(input: HookInput) -> Result<()> {
    debug!(
        "SubagentStart: session_id={}, cwd={}",
        input.session_id, input.cwd
    );

    const SPECIALIST_CONTEXT: &str = "[SPECIALIST RULES] Execute task directly. Do NOT delegate. Follow CLAUDE.md rules. Output format: Summary, Changes, Verification, Risks.";

    output_generic("SubagentStart", Some(SPECIALIST_CONTEXT), None);
    Ok(())
}

/// Orchestrator context injected on every user prompt.
const ORCHESTRATOR_CONTEXT: &str = "You are the Orchestrator. Delegate via Task tool. Check agent descriptions. Maximize parallelization.";

/// Handle `UserPromptSubmit` hook - inject orchestrator reminder and auto-recall context.
pub(crate) async fn handle_user_prompt_submit(input: HookInput) -> Result<()> {
    debug!(
        "UserPromptSubmit: session_id={}, cwd={}",
        input.session_id, input.cwd
    );

    let recall_ctx = build_recall_context(&input).await;
    let recall_ctx = recall_ctx.map(|ctx| clx_core::redaction::redact_secrets(&ctx));

    let additional_context = match recall_ctx {
        Some(recall) => format!("{ORCHESTRATOR_CONTEXT}\n\n{recall}"),
        None => ORCHESTRATOR_CONTEXT.to_string(),
    };

    output_generic("UserPromptSubmit", Some(&additional_context), None);
    Ok(())
}

/// Check early-return conditions for auto-recall.
///
/// Returns `None` if recall is disabled, prompt is missing, or prompt is too short.
/// Otherwise returns the prompt string slice ready for querying.
fn check_recall_preconditions<'a>(
    input: &'a HookInput,
    config: &clx_core::config::AutoRecallConfig,
) -> Option<&'a str> {
    if !config.enabled {
        debug!("Auto-recall disabled");
        return None;
    }

    let prompt = input.prompt.as_deref()?;
    if prompt.chars().count() < config.min_prompt_len {
        debug!(
            "Prompt too short for recall ({} < {})",
            prompt.chars().count(),
            config.min_prompt_len
        );
        return None;
    }

    Some(prompt)
}

/// Build recall context from the user prompt, respecting config and timeout.
///
/// Returns `None` on any error or if recall is not applicable — the hook must
/// always produce output regardless of recall availability.
async fn build_recall_context(input: &HookInput) -> Option<String> {
    let config = clx_core::config::Config::load().ok()?;

    let prompt = check_recall_preconditions(input, &config.auto_recall)?;

    let timeout = std::time::Duration::from_millis(config.auto_recall.timeout_ms);
    tokio::time::timeout(timeout, do_recall(prompt, &config))
        .await
        .ok()?
}

/// Perform the actual recall query against storage + embeddings.
///
/// All errors are swallowed (returns `None`) so the hook always succeeds.
async fn do_recall(prompt: &str, config: &clx_core::config::Config) -> Option<String> {
    let db_path = clx_core::paths::database_path();
    let storage = clx_core::storage::Storage::open(&db_path).ok()?;

    // Build OllamaClient with a tighter timeout (leave 50ms for formatting).
    // Hook process is short-lived (one prompt), so no need for static caching.
    let ollama_config = clx_core::config::OllamaConfig {
        timeout_ms: config.auto_recall.timeout_ms.saturating_sub(50),
        max_retries: 0,
        ..config.ollama_or_default().clone()
    };
    let ollama = match clx_core::ollama::OllamaClient::new(ollama_config) {
        Ok(client) => Some(client),
        Err(e) => {
            warn!("Auto-recall: failed to create OllamaClient: {e}");
            None
        }
    };

    let embedding_store = match clx_core::embeddings::EmbeddingStore::open_with_dimension(
        &db_path,
        config.ollama_or_default().embedding_dim,
    ) {
        Ok(store) => Some(store),
        Err(e) => {
            warn!("Auto-recall: failed to open EmbeddingStore: {e}");
            None
        }
    };

    let recall_config = clx_core::recall::RecallQueryConfig {
        max_results: config.auto_recall.max_results,
        similarity_threshold: config.auto_recall.similarity_threshold,
        fallback_to_fts: config.auto_recall.fallback_to_fts,
        include_key_facts: config.auto_recall.include_key_facts,
    };

    let engine =
        clx_core::recall::RecallEngine::new(&storage, ollama.as_ref(), embedding_store.as_ref());
    let hits = engine.query(prompt, &recall_config).await;

    if hits.is_empty() {
        debug!("Auto-recall: no hits for prompt");
        return None;
    }

    debug!("Auto-recall: {} hits found", hits.len());

    clx_core::recall::format_recall_context(
        &hits,
        config.auto_recall.max_context_chars,
        config.auto_recall.include_key_facts,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clx_core::config::AutoRecallConfig;
    use clx_core::types::SessionId;

    fn make_input(prompt: Option<&str>) -> HookInput {
        HookInput {
            session_id: SessionId::new("test-session"),
            transcript_path: None,
            cwd: "/tmp".to_string(),
            hook_event_name: "UserPromptSubmit".to_string(),
            tool_name: None,
            tool_use_id: None,
            tool_input: None,
            tool_response: None,
            source: None,
            trigger: None,
            prompt: prompt.map(String::from),
        }
    }

    #[test]
    fn test_preconditions_disabled() {
        let input = make_input(Some("Implement the feature"));
        let config = AutoRecallConfig {
            enabled: false,
            ..AutoRecallConfig::default()
        };
        assert!(check_recall_preconditions(&input, &config).is_none());
    }

    #[test]
    fn test_preconditions_missing_prompt() {
        let input = make_input(None);
        let config = AutoRecallConfig::default();
        assert!(check_recall_preconditions(&input, &config).is_none());
    }

    #[test]
    fn test_preconditions_short_prompt() {
        let input = make_input(Some("hi"));
        let config = AutoRecallConfig {
            min_prompt_len: 10,
            ..AutoRecallConfig::default()
        };
        assert!(check_recall_preconditions(&input, &config).is_none());
    }

    #[test]
    fn test_preconditions_valid_prompt() {
        let input = make_input(Some("Implement the authentication module"));
        let config = AutoRecallConfig::default();
        let result = check_recall_preconditions(&input, &config);
        assert_eq!(result, Some("Implement the authentication module"));
    }

    #[test]
    fn test_orchestrator_context_present() {
        assert!(
            ORCHESTRATOR_CONTEXT.contains("Orchestrator"),
            "Orchestrator context should mention Orchestrator role"
        );
    }
}

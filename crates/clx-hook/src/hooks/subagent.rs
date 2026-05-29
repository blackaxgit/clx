//! `SubagentStart` and `UserPromptSubmit` hook handlers.

use std::sync::Once;

use anyhow::Result;
use tracing::{debug, warn};

use crate::host::Host;
use crate::output::output_generic;
use crate::types::HostNeutralInput;

/// Guards the per-process spawn of `clx model fetch --background` so we
/// only kick off a single download attempt regardless of how many user
/// prompts land before the model is ready.
static MODEL_PREFETCH_ONCE: Once = Once::new();

/// Handle `SubagentStart` hook - inject specialist rules into subagent context
pub(crate) async fn handle_subagent_start(input: HostNeutralInput, _host: &dyn Host) -> Result<()> {
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
pub(crate) async fn handle_user_prompt_submit(
    input: HostNeutralInput,
    _host: &dyn Host,
) -> Result<()> {
    debug!(
        "UserPromptSubmit: session_id={}, cwd={}",
        input.session_id, input.cwd
    );

    // D2 first-run UX: if the reranker model is missing, spawn a
    // background fetch exactly once per process. Always cheap; the
    // OnceLock + filesystem check returns in microseconds.
    maybe_prefetch_reranker_model();

    let recall_ctx = build_recall_context(&input).await;
    let recall_ctx = recall_ctx.map(|ctx| clx_core::redaction::redact_secrets(&ctx));

    let additional_context = match recall_ctx {
        Some(recall) => format!("{ORCHESTRATOR_CONTEXT}\n\n{recall}"),
        None => ORCHESTRATOR_CONTEXT.to_string(),
    };

    output_generic("UserPromptSubmit", Some(&additional_context), None);
    Ok(())
}

/// One-shot prefetch of the bge-reranker-v2-m3 model on first user
/// prompt of the hook process.
///
/// * Returns immediately if the model is already ready (cheap fs check).
/// * Returns immediately if `auto_recall.reranker_enabled = false`.
/// * Otherwise spawns `clx model fetch --background` exactly once per
///   process via `std::sync::Once` and emits a single WARN.
fn maybe_prefetch_reranker_model() {
    let cache_dir = clx_core::paths::model_cache_dir();
    if clx_core::recall::FastembedReranker::ready_at(&cache_dir) {
        return;
    }

    // Respect the user's opt-out before doing any work.
    match clx_core::config::Config::load() {
        Ok(config) if !config.auto_recall.reranker_enabled => return,
        Err(_) => return, // Config missing or invalid: skip prefetch.
        _ => {}
    }

    MODEL_PREFETCH_ONCE.call_once(|| {
        warn!(
            "bge-reranker-v2-m3 not yet downloaded (~568 MB). Spawning \
             background fetch; recall will use RRF-only until ready. \
             Track progress via `clx model status`."
        );
        if let Err(e) = spawn_background_fetch() {
            warn!("background `clx model fetch` failed to launch: {e}");
        }
    });
}

/// Spawn `clx model fetch --background` detached from the hook process.
fn spawn_background_fetch() -> std::io::Result<()> {
    // Resolve the `clx` binary that sits next to this hook binary so
    // we do not rely on `clx` being on PATH.
    let exe = std::env::current_exe()?;
    let clx_binary = exe
        .parent()
        .map(|p| p.join("clx"))
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("clx"));

    std::process::Command::new(clx_binary)
        .args(["model", "fetch", "--background"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    Ok(())
}

/// Check early-return conditions for auto-recall.
///
/// Returns `None` if recall is disabled, prompt is missing, or prompt is too short.
/// Otherwise returns the prompt string slice ready for querying.
fn check_recall_preconditions<'a>(
    input: &'a HostNeutralInput,
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
/// Returns `None` on any error or if recall is not applicable. The hook must
/// always produce output regardless of recall availability.
async fn build_recall_context(input: &HostNeutralInput) -> Option<String> {
    let config = clx_core::config::Config::load().ok()?;

    let prompt = check_recall_preconditions(input, &config.auto_recall)?;

    let session_id = input.session_id.as_str();
    let timeout = std::time::Duration::from_millis(config.auto_recall.timeout_ms);
    tokio::time::timeout(timeout, do_recall(prompt, session_id, &config))
        .await
        .ok()?
}

/// Perform the actual recall query against storage + embeddings.
///
/// All errors are swallowed (returns `None`) so the hook always succeeds.
/// When `auto_recall.pin_recent_sessions.enabled` is true, the last-N
/// session summaries are prepended as a header block (current session
/// excluded via `session_id`). Pinning failures degrade gracefully: the
/// recall context is returned unchanged.
async fn do_recall(
    prompt: &str,
    session_id: &str,
    config: &clx_core::config::Config,
) -> Option<String> {
    let db_path = clx_core::paths::database_path();
    let storage = clx_core::storage::Storage::open(&db_path).ok()?;

    // Build LLM client for embeddings via factory.
    let ollama = match config.create_llm_client(clx_core::config::Capability::Embeddings) {
        Ok(client) => Some(client),
        Err(e) => {
            warn!("Auto-recall: failed to create LLM client: {e}");
            None
        }
    };

    let embed_dim = config.ollama.as_ref().map_or_else(
        || clx_core::config::OllamaConfig::default().embedding_dim,
        |o| o.embedding_dim,
    );

    let embedding_store =
        match clx_core::embeddings::EmbeddingStore::open_with_dimension(&db_path, embed_dim) {
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
        rrf_enabled: config.auto_recall.rrf_enabled,
        rrf_k: config.auto_recall.rrf_k,
        time_decay_half_life_days: config.auto_recall.time_decay_half_life_days,
        percentile_gate: query_percentile_gate(config.auto_recall.percentile_gate),
        reranker_enabled: config.auto_recall.reranker_enabled,
        reranker_timeout_ms: config.auto_recall.reranker_timeout_ms,
    };

    let reranker = config
        .auto_recall
        .reranker_enabled
        .then(|| clx_core::recall::FastembedReranker::new(clx_core::paths::model_cache_dir()));

    // Build domain ports (Hexagonal Architecture, 0.8.0). The engine speaks
    // only to traits; concrete Storage / EmbeddingStore / LlmClient stay in
    // the Infrastructure layer behind these adapters.
    let repo = clx_core::storage::StorageSnapshotRepo::new(&storage, embedding_store.as_ref());
    let embedding_model = config
        .capability_route(clx_core::config::Capability::Embeddings)
        .ok()
        .map(|route| route.model.clone());
    let embedder = ollama
        .as_ref()
        .map(|client| clx_core::recall::LlmQueryEmbedder::new(client, embedding_model.as_deref()));

    let mut engine = clx_core::recall::RecallEngine::new(&repo);
    if let Some(ref e) = embedder {
        engine = engine.with_embedder(e);
    }
    if let Some(reranker) = reranker.as_ref() {
        engine = engine.with_reranker(reranker);
    }
    let hits = engine.query(prompt, &recall_config).await;

    let pinned_block = build_pinned_block(&storage, session_id, &config.auto_recall);

    if hits.is_empty() {
        debug!("Auto-recall: no hits for prompt");
        // When pinned-block is the only available context still emit it
        // so the user sees recent session anchors even with zero hits.
        return pinned_block;
    }

    debug!("Auto-recall: {} hits found", hits.len());

    let recall_body = clx_core::recall::format_recall_context(
        &hits,
        config.auto_recall.max_context_chars,
        config.auto_recall.include_key_facts,
    );

    match (pinned_block, recall_body) {
        (Some(pinned), Some(body)) => Some(format!("{pinned}\n{body}")),
        (Some(pinned), None) => Some(pinned),
        (None, Some(body)) => Some(body),
        (None, None) => None,
    }
}

fn query_percentile_gate(value: f64) -> u32 {
    if !value.is_finite() || value <= 0.0 {
        0
    } else {
        (value.clamp(0.0, 1.0) * 100.0).round() as u32
    }
}

/// Build the pinned recent-sessions block when configured.
///
/// Returns `None` if pinning is disabled, the storage query errors, or the
/// database has no eligible sessions. Errors are logged at warn but never
/// propagated. The recall hook must always make forward progress.
fn build_pinned_block(
    storage: &clx_core::storage::Storage,
    session_id: &str,
    cfg: &clx_core::config::AutoRecallConfig,
) -> Option<String> {
    let pin_cfg = &cfg.pin_recent_sessions;
    if !pin_cfg.enabled || pin_cfg.count == 0 {
        return None;
    }

    let exclude = if session_id.is_empty() {
        None
    } else {
        Some(session_id)
    };

    match storage.recent_session_summaries(pin_cfg.count, exclude) {
        Ok(summaries) if !summaries.is_empty() => {
            clx_core::recall::format_pinned_block(&summaries, pin_cfg.max_chars_each)
        }
        Ok(_) => None,
        Err(e) => {
            warn!("Auto-recall: pinned-session query failed: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clx_core::config::AutoRecallConfig;
    use clx_core::types::SessionId;

    fn make_input(prompt: Option<&str>) -> HostNeutralInput {
        HostNeutralInput {
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
            direct_command: None,
            host: crate::host::HostId::Claude,
            extras: std::collections::HashMap::new(),
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

    // --- build_pinned_block (Phase C2: pin recent sessions) ---

    use clx_core::config::PinRecentSessionsConfig;
    use clx_core::storage::Storage;
    use clx_core::types::{Session, Snapshot, SnapshotTrigger};

    fn auto_cfg(pin: PinRecentSessionsConfig) -> AutoRecallConfig {
        AutoRecallConfig {
            pin_recent_sessions: pin,
            ..AutoRecallConfig::default()
        }
    }

    fn seed(storage: &Storage, id: &str, secs_ago: i64, summary: &str) {
        let now = chrono::Utc::now();
        let started = now - chrono::Duration::seconds(secs_ago);
        let mut s = Session::new(SessionId::new(id), "/tmp/proj".to_string());
        s.started_at = started;
        storage.create_session(&s).unwrap();
        let mut snap = Snapshot::new(SessionId::new(id), SnapshotTrigger::Auto);
        snap.created_at = started + chrono::Duration::seconds(1);
        snap.summary = Some(summary.to_string());
        storage.create_snapshot(&snap).unwrap();
    }

    #[test]
    fn pinned_block_disabled_returns_none() {
        let storage = Storage::open_in_memory().unwrap();
        seed(&storage, "sess-1", 10, "anything");
        let cfg = auto_cfg(PinRecentSessionsConfig {
            enabled: false,
            count: 5,
            max_chars_each: 300,
        });
        assert!(build_pinned_block(&storage, "current", &cfg).is_none());
    }

    #[test]
    fn pinned_block_zero_count_returns_none() {
        let storage = Storage::open_in_memory().unwrap();
        seed(&storage, "sess-1", 10, "anything");
        let cfg = auto_cfg(PinRecentSessionsConfig {
            enabled: true,
            count: 0,
            max_chars_each: 300,
        });
        assert!(build_pinned_block(&storage, "current", &cfg).is_none());
    }

    #[test]
    fn pinned_block_enabled_renders_block() {
        let storage = Storage::open_in_memory().unwrap();
        seed(&storage, "sess-a", 100, "alpha decision");
        seed(&storage, "sess-b", 50, "beta decision");
        let cfg = auto_cfg(PinRecentSessionsConfig {
            enabled: true,
            count: 5,
            max_chars_each: 300,
        });
        let out = build_pinned_block(&storage, "current-id", &cfg).expect("block present");
        assert!(out.contains("## Pinned recent sessions"));
        assert!(out.contains("sess-a"));
        assert!(out.contains("sess-b"));
    }

    #[test]
    fn pinned_block_excludes_current_session() {
        let storage = Storage::open_in_memory().unwrap();
        seed(&storage, "sess-keep", 100, "keep me");
        seed(&storage, "sess-drop", 50, "drop me");
        let cfg = auto_cfg(PinRecentSessionsConfig {
            enabled: true,
            count: 5,
            max_chars_each: 300,
        });
        let out = build_pinned_block(&storage, "sess-drop", &cfg).expect("block present");
        assert!(out.contains("sess-keep"));
        assert!(
            !out.contains("[sess-drop]"),
            "current session must be excluded, got: {out}"
        );
    }

    #[test]
    fn pinned_block_empty_session_id_does_not_self_pin() {
        // When called with an empty session_id (e.g., before SessionStart row
        // exists), exclusion must be skipped gracefully and the block still
        // renders all available sessions.
        let storage = Storage::open_in_memory().unwrap();
        seed(&storage, "sess-x", 10, "x");
        let cfg = auto_cfg(PinRecentSessionsConfig {
            enabled: true,
            count: 5,
            max_chars_each: 300,
        });
        let out = build_pinned_block(&storage, "", &cfg).expect("block present");
        assert!(out.contains("sess-x"));
    }

    #[test]
    fn pinned_block_empty_db_returns_none() {
        let storage = Storage::open_in_memory().unwrap();
        let cfg = auto_cfg(PinRecentSessionsConfig {
            enabled: true,
            count: 3,
            max_chars_each: 300,
        });
        assert!(build_pinned_block(&storage, "anything", &cfg).is_none());
    }
}

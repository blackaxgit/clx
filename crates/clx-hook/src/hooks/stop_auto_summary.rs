//! `Stop` hook handler: rolling N-turn auto-summarization (Phase 10 / 0.8.0).
//!
//! Opt-in. Gated by `memory.auto_summarize.enabled`. When enabled, this
//! handler:
//!
//! 1. Counts assistant turns since the last `AutoSummary` snapshot for
//!    the current session (`turns_since_last_auto_summary`).
//! 2. If `turns_since < every_n_turns`, returns immediately.
//! 3. If `skip_when_idle` is set and no mutating tool events have been
//!    recorded since the last summary, returns immediately.
//! 4. Reads the trailing N turns from the transcript JSONL file.
//! 5. Calls the configured summarizer LLM via
//!    `Config::create_llm_client(...)`; falls back to a deterministic
//!    template when the LLM is unavailable or errors.
//! 6. Persists a new `Snapshot` row tagged
//!    `SnapshotTrigger::AutoSummary`.
//!
//! All error paths swallow into `Ok(())` so the Stop hook never causes a
//! non-zero exit code (Claude Code treats those as hook failure noise).
//! The whole call is wrapped in a soft timeout so a hung provider can't
//! delay session exit.

use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use clx_core::config::{AutoSummarizeConfig, Capability, Config};
use clx_core::storage::Storage;
use clx_core::summarize::{TurnSlice, summarize_turns};
use clx_core::types::{Snapshot, SnapshotTrigger};
use tracing::{debug, warn};

use crate::transcript::{OwnedTurn, last_n_turns};
use crate::types::HookInput;

/// Hard ceiling on the entire handler's wall-clock time. The LLM call is
/// the dominant cost; this guards against any wedge in the provider
/// returning before Claude Code's own Stop-hook budget elapses.
const HANDLER_TIMEOUT: Duration = Duration::from_secs(10);

/// Number of trailing transcript turns we feed the summarizer. Larger
/// spans waste prompt tokens for low-marginal recall; `2 * every_n_turns`
/// gives a comfortable window without inflating costs.
fn turns_to_sample(cfg: &AutoSummarizeConfig) -> usize {
    let n = cfg.every_n_turns as usize;
    n.saturating_mul(2).max(2)
}

/// Public entry point invoked from the Stop event router.
pub(crate) async fn handle_stop_auto_summary(input: HookInput) -> Result<()> {
    // Soft timeout: if the LLM call (or anything else) wedges, abandon
    // the summary attempt and let the Stop event complete cleanly.
    let _ = tokio::time::timeout(HANDLER_TIMEOUT, run_inner(input)).await;
    Ok(())
}

async fn run_inner(input: HookInput) -> Result<()> {
    // Capture the moment this handler started. Used as the optimistic-
    // concurrency reference point for the duplicate-snapshot guard below.
    let started_at = Utc::now();

    let config = Config::load().unwrap_or_default();
    if !config.memory.auto_summarize.enabled {
        debug!("auto-summary: disabled in config, skipping");
        return Ok(());
    }

    let cfg = config.memory.auto_summarize.clone();
    if cfg.every_n_turns == 0 {
        warn!("auto-summary: every_n_turns must be >= 1; clamping to 1");
    }
    let threshold = cfg.every_n_turns.max(1);

    let storage = match Storage::open_default() {
        Ok(s) => s,
        Err(e) => {
            warn!("auto-summary: cannot open storage: {e}");
            return Ok(());
        }
    };

    let session_id = input.session_id.as_str();
    let turns_since = match storage.turns_since_last_auto_summary(session_id) {
        Ok(n) => n,
        Err(e) => {
            warn!("auto-summary: turn-count query failed: {e}");
            return Ok(());
        }
    };

    if turns_since < threshold {
        debug!(
            "auto-summary: {} < {} turns since last summary, skipping",
            turns_since, threshold
        );
        return Ok(());
    }

    if cfg.skip_when_idle {
        match storage.had_mutator_activity_since_last_auto_summary(session_id) {
            Ok(true) => { /* proceed */ }
            Ok(false) => {
                debug!(
                    "auto-summary: skip_when_idle=true and no tool_events since last summary"
                );
                return Ok(());
            }
            Err(e) => {
                warn!("auto-summary: idle check failed: {e}");
                // Conservative: proceed rather than silently skip.
            }
        }
    }

    let transcript_path = match input.transcript_path.as_deref() {
        Some(p) => p,
        None => {
            debug!("auto-summary: no transcript_path on hook envelope");
            return Ok(());
        }
    };
    let sample = turns_to_sample(&cfg);
    let turns_owned = last_n_turns(transcript_path, sample);
    if turns_owned.is_empty() {
        debug!("auto-summary: transcript empty, skipping");
        return Ok(());
    }

    let summary = build_summary(&config, &cfg, &turns_owned).await;
    let summary = match summary {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            debug!("auto-summary: empty summary body, not persisting");
            return Ok(());
        }
    };

    // Optimistic-concurrency gate: re-fetch the last AutoSummary timestamp
    // immediately before persisting. If another Stop-hook handler ran in
    // parallel and already wrote a snapshot after this handler started,
    // skip writing to avoid duplicate AutoSummary snapshots for the same
    // session/window. Storage::create_snapshot is the boundary we cannot
    // wrap in a single SQL statement; this check is the tightest possible
    // re-read before the insert.
    match storage.last_auto_summary_at(session_id) {
        Ok(Some(last)) if last >= started_at => {
            debug!(
                "auto-summary: another handler wrote a snapshot at {} after this handler started at {}; skipping",
                last, started_at
            );
            return Ok(());
        }
        Ok(_) => { /* no concurrent writer; proceed */ }
        Err(e) => {
            // Conservative on query failure: proceed rather than silently skip.
            warn!("auto-summary: duplicate-snapshot guard query failed: {e}");
        }
    }

    let mut snap = Snapshot::new(input.session_id.clone(), SnapshotTrigger::AutoSummary);
    snap.summary = Some(summary);
    snap.message_count = i32::try_from(turns_since).ok();
    if let Err(e) = storage.create_snapshot(&snap) {
        warn!("auto-summary: failed to persist snapshot: {e}");
        return Ok(());
    }
    debug!(
        "auto-summary: persisted snapshot for session {} (turns_since={})",
        session_id, turns_since
    );
    Ok(())
}

async fn build_summary(
    config: &Config,
    cfg: &AutoSummarizeConfig,
    turns: &[OwnedTurn],
) -> Option<String> {
    let capability = parse_capability(&cfg.summarizer_capability);
    let llm = config.create_llm_client(capability).ok();
    let route = config.capability_route(capability).ok();

    let slices: Vec<TurnSlice<'_>> = turns
        .iter()
        .map(|t| TurnSlice {
            role: t.role.as_str(),
            content: t.content.as_str(),
        })
        .collect();

    match summarize_turns(&slices, cfg, llm.as_ref(), route).await {
        Ok(s) => Some(s),
        Err(e) => {
            warn!("auto-summary: summarize_turns errored: {e}");
            None
        }
    }
}

/// Map the free-form `summarizer_capability` string back to the typed
/// `Capability`. Unknown values fall back to `Chat` (the documented
/// default in `AutoSummarizeConfig::default()`).
fn parse_capability(s: &str) -> Capability {
    match s.to_ascii_lowercase().as_str() {
        "embeddings" | "embedding" => Capability::Embeddings,
        _ => Capability::Chat,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clx_core::config::{AutoSummarizeConfig, MemoryConfig};
    use clx_core::types::SessionId;

    fn input_with_session(session: &str) -> HookInput {
        HookInput {
            session_id: SessionId::new(session),
            transcript_path: None,
            cwd: "/tmp".to_string(),
            hook_event_name: "Stop".to_string(),
            tool_name: None,
            tool_use_id: None,
            tool_input: None,
            tool_response: None,
            source: None,
            trigger: None,
            prompt: None,
        }
    }

    #[test]
    fn turns_to_sample_doubles_threshold() {
        let cfg = AutoSummarizeConfig {
            every_n_turns: 5,
            ..AutoSummarizeConfig::default()
        };
        assert_eq!(turns_to_sample(&cfg), 10);
    }

    #[test]
    fn turns_to_sample_minimum_floor_is_two() {
        let cfg = AutoSummarizeConfig {
            every_n_turns: 0,
            ..AutoSummarizeConfig::default()
        };
        assert_eq!(turns_to_sample(&cfg), 2);
    }

    #[test]
    fn parse_capability_unknown_falls_back_to_chat() {
        assert!(matches!(parse_capability("bogus"), Capability::Chat));
        assert!(matches!(parse_capability(""), Capability::Chat));
    }

    #[test]
    fn parse_capability_embeddings_aliases() {
        assert!(matches!(
            parse_capability("embeddings"),
            Capability::Embeddings
        ));
        assert!(matches!(
            parse_capability("embedding"),
            Capability::Embeddings
        ));
        assert!(matches!(parse_capability("Chat"), Capability::Chat));
    }

    /// Smoke: disabled config is a clean no-op. Stop hook must not error
    /// when the user has not opted in.
    #[serial_test::serial]
    #[tokio::test]
    async fn handle_stop_disabled_returns_ok() {
        // We can't reliably swap Config::load() at runtime, so this test
        // exercises the public entrypoint with the default config (which
        // has auto_summarize.enabled = false). The handler must not panic
        // and must return Ok(()).
        let input = input_with_session("stop-disabled-noop");
        let result = handle_stop_auto_summary(input).await;
        assert!(result.is_ok());
    }

    #[test]
    fn memory_default_disables_auto_summary() {
        let m = MemoryConfig::default();
        assert!(!m.auto_summarize.enabled);
        assert_eq!(m.auto_summarize.every_n_turns, 5);
        assert_eq!(m.auto_summarize.max_summary_chars, 500);
        assert!(m.auto_summarize.skip_when_idle);
        assert_eq!(m.auto_summarize.summarizer_capability, "chat");
    }
}

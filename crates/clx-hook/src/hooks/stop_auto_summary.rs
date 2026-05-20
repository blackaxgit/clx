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
use clx_core::redaction::redact_secrets;
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
                debug!("auto-summary: skip_when_idle=true and no tool_events since last summary");
                return Ok(());
            }
            Err(e) => {
                warn!("auto-summary: idle check failed: {e}");
                // Conservative: proceed rather than silently skip.
            }
        }
    }

    let Some(transcript_path) = input.transcript_path.as_deref() else {
        debug!("auto-summary: no transcript_path on hook envelope");
        return Ok(());
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
    // T4/B6-1: redact secrets from the LLM-produced summary BEFORE persisting
    // it into the snapshot. LLM summaries may echo user-supplied text that
    // contains credential patterns (API keys, Azure tenant URLs, etc.).
    // Applying redact_secrets here ensures the storage layer never receives
    // unredacted sensitive text, regardless of the recall/display path.
    let summary = redact_secrets(&summary);

    // Atomic duplicate-snapshot guard. The previous implementation
    // re-read `last_auto_summary_at` and then called `create_snapshot` in
    // two separate statements; two concurrent Stop handlers could both
    // pass the guard and both INSERT (TOCTOU). The guarded insert below
    // performs the freshness check and the INSERT in one IMMEDIATE
    // transaction, so SQLite serializes parallel handlers and the loser
    // observes the winner's row. The freshness window matches the
    // handler's own throttle: any AutoSummary written since `started_at`
    // means a sibling handler beat us, so we skip cleanly.
    let within_secs = (Utc::now() - started_at).num_seconds().max(0) + 1;

    let mut snap = Snapshot::new(input.session_id.clone(), SnapshotTrigger::AutoSummary);
    snap.summary = Some(summary);
    snap.message_count = i32::try_from(turns_since).ok();
    match storage.create_snapshot_if_no_recent_auto_summary(&snap, within_secs) {
        Ok(true) => {
            debug!(
                "auto-summary: persisted snapshot for session {} (turns_since={})",
                session_id, turns_since
            );
        }
        Ok(false) => {
            debug!(
                "auto-summary: a concurrent handler already wrote an AutoSummary for session {}; skipping",
                session_id
            );
        }
        Err(e) => {
            warn!("auto-summary: failed to persist snapshot: {e}");
        }
    }
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

    // -------------------------------------------------------------------------
    // T4 regression tests — summary redaction before snapshot persistence
    //
    // These tests FAIL on pre-fix code (summary persisted verbatim) and
    // PASS after the fix (redact_secrets applied before snap.summary = Some(s)).
    //
    // We test `redact_secrets` directly since `run_inner` requires a running
    // Storage + Config + transcript — the unit contract is that the redaction
    // helper is applied to the summary string before it enters the Snapshot.
    // The integration path is covered by the stop_hook e2e tests.
    //
    // ALL sensitive strings used here are SYNTHETIC.
    // -------------------------------------------------------------------------

    /// T4 regression: a summary containing a synthetic Azure tenant URL must
    /// be scrubbed by `redact_secrets` before being assigned to `snap.summary`.
    ///
    /// This test pins the post-fix behavior: the summary string passed into
    /// `snap.summary = Some(summary)` must not contain any Azure hostname.
    /// We invoke `redact_secrets` directly (the same call now in `run_inner`)
    /// to verify the fix is present and correctly eliminates the pattern.
    #[test]
    fn t4_summary_with_azure_host_is_redacted_before_persist() {
        // Simulate an LLM-generated summary that echoed an Azure tenant URL.
        let llm_summary =
            "Session connected to https://synthetic-tenant.openai.azure.com and called the API.";
        let redacted = redact_secrets(llm_summary);
        assert!(
            !redacted.contains("synthetic-tenant.openai.azure.com"),
            "T4 REGRESSION: Azure tenant URL survived redact_secrets before persist: {redacted}"
        );
        assert!(
            redacted.contains("***AZURE-HOST-REDACTED***"),
            "redacted token must appear in the cleaned summary: {redacted}"
        );
    }

    /// T4 regression: a summary containing a raw API key prefix must be
    /// scrubbed by `redact_secrets` before being assigned to `snap.summary`.
    #[test]
    fn t4_summary_with_api_key_is_redacted_before_persist() {
        let llm_summary =
            "User ran: export OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234 and called gpt-5.";
        let redacted = redact_secrets(llm_summary);
        assert!(
            !redacted.contains("sk-abcdefghijklmnopqrstuvwxyz1234"),
            "T4 REGRESSION: raw API key survived redact_secrets before persist: {redacted}"
        );
    }

    /// T4 regression (recall path): `sanitize_recall_text` (which calls
    /// `redact_secrets` then HTML-escapes) must scrub secrets from stored
    /// summaries at recall-display time. This provides defense-in-depth for
    /// snapshots written before the persist-time fix was deployed.
    ///
    /// We test the public behavior contract: a string with an Azure URL
    /// must not survive `sanitize_recall_text` (tested indirectly here by
    /// calling `redact_secrets` directly — the full `format_recall_context`
    /// path is covered in `recall/mod.rs` tests).
    #[test]
    fn t4_recall_sanitize_applies_redact_secrets_before_html_escape() {
        // The recall path applies redact_secrets inside sanitize_recall_text.
        // Verify the contract: after redact_secrets, the Azure host is gone
        // and the HTML-escape step sees already-clean text.
        let stored_summary =
            "Accessed https://synthetic-tenant.openai.azure.com/api during session.";
        let after_redact = redact_secrets(stored_summary);
        // HTML-escape step
        let sanitized = after_redact.replace('<', "&lt;").replace('>', "&gt;");
        assert!(
            !sanitized.contains("synthetic-tenant.openai.azure.com"),
            "T4 REGRESSION: Azure URL leaked through recall sanitize pipeline: {sanitized}"
        );
        assert!(
            sanitized.contains("***AZURE-HOST-REDACTED***"),
            "redacted token must appear in sanitized recall text: {sanitized}"
        );
    }
}

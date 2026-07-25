//! `PreCompact` hook handler - create snapshot before context compression.

use std::time::Duration;

use anyhow::Result;
use clx_core::storage::Storage;
use clx_core::types::{Session, Snapshot, SnapshotTrigger};
use tracing::{debug, error, info, warn};

use crate::embedding::generate_and_store_embedding;
use crate::host::Host;
use crate::transcript::process_transcript;
use crate::types::{HostNeutralInput, TranscriptResult};

/// Hard ceiling on the entire handler's wall-clock time. `process_transcript`
/// may invoke an LLM summarizer; unlike `session_end` (1s) and
/// `stop_auto_summary` (10s), this handler previously wrapped no timeout at
/// all, so a wedged provider (or a slow/huge transcript) could hang the
/// `PreCompact` event indefinitely (P2-1). Mirrors the
/// `stop_auto_summary::HANDLER_TIMEOUT` idiom: a soft timeout around the
/// whole inner implementation, logging and returning `Ok(())` on elapse so
/// the hook always exits cleanly rather than hanging or panicking.
const PRE_COMPACT_TIMEOUT: Duration = Duration::from_secs(10);

/// Handle `PreCompact` hook - create snapshot before context compression.
///
/// Wraps the inner implementation in a timeout so a slow/wedged transcript
/// summarization can never hang the `PreCompact` event (P2-1).
pub(crate) async fn handle_pre_compact(input: HostNeutralInput, host: &dyn Host) -> Result<()> {
    let session_id = input.session_id.clone();
    if let Ok(result) =
        tokio::time::timeout(PRE_COMPACT_TIMEOUT, handle_pre_compact_inner(input, host)).await
    {
        result
    } else {
        warn!(
            "PreCompact: timed out after {}s for session {}, skipping remaining work",
            PRE_COMPACT_TIMEOUT.as_secs(),
            session_id
        );
        Ok(())
    }
}

/// Inner implementation that does the actual work (see `handle_pre_compact`
/// for the timeout wrapper).
async fn handle_pre_compact_inner(input: HostNeutralInput, _host: &dyn Host) -> Result<()> {
    let trigger = input.trigger.as_deref().unwrap_or("auto");

    info!(
        "PreCompact: Creating snapshot for session {} (trigger: {})",
        input.session_id, trigger
    );

    // Open storage
    let storage = match Storage::open_default() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to open storage: {}", e);
            return Ok(());
        }
    };

    // Read and process transcript if available
    let result = if let Some(transcript_path) = &input.transcript_path {
        process_transcript(transcript_path, true).await
    } else {
        TranscriptResult {
            summary: None,
            key_facts: None,
            todos: None,
            message_count: None,
            input_tokens: 0,
            output_tokens: 0,
        }
    };

    // Create snapshot
    let snapshot_trigger = match trigger {
        "manual" => SnapshotTrigger::Manual,
        "auto" => SnapshotTrigger::Auto,
        _ => SnapshotTrigger::Auto,
    };

    let mut snapshot = Snapshot::new(input.session_id.clone(), snapshot_trigger);
    snapshot.summary = result.summary.clone();
    snapshot.key_facts = result.key_facts;
    snapshot.todos = result.todos;
    snapshot.message_count = result.message_count;
    snapshot.input_tokens = Some(result.input_tokens);
    snapshot.output_tokens = Some(result.output_tokens);

    // P1-5-precompact: ensure the session row exists before inserting the
    // snapshot. `snapshots` carries a FK on `sessions`; if PreCompact is the
    // first event storage sees for this session_id (e.g. SessionStart never
    // ran for this host/ordering, or a resumed session), the insert below
    // fails on the FK constraint and the error was merely logged below —
    // the snapshot was silently lost. Mirror the ensure-or-create pattern
    // used by `clx-mcp/src/tools/remember.rs` (`tool_remember`).
    if storage
        .get_session(input.session_id.as_str())
        .ok()
        .flatten()
        .is_none()
    {
        let session = Session::new(input.session_id.clone(), input.cwd.clone());
        if let Err(e) = storage.create_session(&session) {
            warn!(
                "Failed to ensure session {} exists before snapshot insert: {}",
                input.session_id, e
            );
        }
    }

    // Store the snapshot
    match storage.create_snapshot(&snapshot) {
        Ok(snapshot_id) => {
            debug!(
                "Created snapshot {} for session {}",
                snapshot_id, input.session_id
            );

            // Try to generate and store embedding for the snapshot summary
            if let Some(ref summary_text) = snapshot.summary
                && let Err(e) = generate_and_store_embedding(snapshot_id, summary_text).await
            {
                warn!("Failed to store embedding: {}", e);
            }

            // Update session with token counts
            if let Ok(Some(mut session)) = storage.get_session(input.session_id.as_str()) {
                session.input_tokens = result.input_tokens;
                session.output_tokens = result.output_tokens;
                if let Err(e) = storage.update_session(&session) {
                    warn!("Failed to update session tokens: {}", e);
                }
            }

            debug!(
                "Snapshot saved before compression ({} messages, ~{} tokens, trigger: {})",
                result.message_count.unwrap_or(0),
                result.input_tokens + result.output_tokens,
                trigger
            );
        }
        Err(e) => {
            error!("Failed to create snapshot: {}", e);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn timeout_constant_matches_stated_budget() {
        assert_eq!(PRE_COMPACT_TIMEOUT, Duration::from_secs(10));
    }

    /// P2-1 regression: pins the exact timeout-wrapping idiom used by
    /// `handle_pre_compact` (`tokio::time::timeout(PRE_COMPACT_TIMEOUT, ..)`)
    /// against a future that never completes. Runs on paused virtual time so
    /// the test proves the wrap elapses at the budget instead of hanging,
    /// without an actual multi-second wall-clock wait.
    ///
    /// FAIL-BEFORE: `handle_pre_compact` wrapped no timeout at all, so a
    /// wedged LLM/transcript call inside `process_transcript` would hang the
    /// `PreCompact` event indefinitely.
    /// PASS-AFTER: the wrapper elapses at `PRE_COMPACT_TIMEOUT` and the
    /// outer `handle_pre_compact` maps that to a clean `Ok(())`.
    #[tokio::test(start_paused = true)]
    async fn timeout_wrapper_elapses_instead_of_hanging_forever() {
        let never_completes = std::future::pending::<()>();
        let wrapped = tokio::time::timeout(PRE_COMPACT_TIMEOUT, never_completes);
        tokio::pin!(wrapped);

        // Advance virtual time just past the budget. A genuine hang would
        // never resolve regardless of how far time is advanced.
        tokio::time::advance(PRE_COMPACT_TIMEOUT + Duration::from_millis(1)).await;

        let result = wrapped.await;
        assert!(
            result.is_err(),
            "timeout must elapse for a future that never completes, proving the handler cannot hang"
        );
    }

    fn input_for(session_id: &str, cwd: &str, transcript_path: Option<String>) -> HostNeutralInput {
        HostNeutralInput {
            session_id: clx_core::types::SessionId::new(session_id),
            transcript_path,
            cwd: cwd.to_string(),
            hook_event_name: "PreCompact".to_string(),
            tool_name: None,
            tool_use_id: None,
            tool_input: None,
            tool_response: None,
            source: None,
            trigger: Some("auto".to_string()),
            prompt: None,
            direct_command: None,
            host: crate::host::HostId::Claude,
            extras: std::collections::HashMap::new(),
        }
    }

    /// P1-5-precompact regression: `PreCompact` firing for a session that
    /// storage has never seen before (no prior `SessionStart`) must not
    /// silently lose the snapshot to the `snapshots` -> `sessions` FK
    /// constraint. Also exercises the P2-1 timeout wrapper end-to-end,
    /// asserting the whole handler completes well within budget on the
    /// normal (non-hanging) path.
    ///
    /// FAIL-BEFORE: `create_snapshot` hit the FK constraint because no
    /// `sessions` row existed for `session_id`; the error was logged and
    /// swallowed, so `get_snapshots_by_session` below would return empty.
    /// PASS-AFTER: the session is ensured-or-created first, the insert
    /// succeeds, and the snapshot is retrievable.
    #[tokio::test]
    #[serial_test::serial(clx_home)]
    async fn handle_pre_compact_ensures_session_before_snapshot_insert() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let temp_home = std::env::temp_dir().join(format!(
            "clx-pre-compact-ensure-session-{}-{}",
            std::process::id(),
            unique
        ));
        std::fs::create_dir_all(&temp_home).unwrap();

        // SAFETY (test-only): redirect HOME so Storage::open_default() opens
        // an isolated DB instead of the developer's real ~/.clx state. No
        // other test in this process shares this env var mutation window;
        // this test does not run concurrently with itself.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("HOME", temp_home.to_str().unwrap());
        }

        let session_id = "precompact-fk-regression-session";
        let input = input_for(session_id, temp_home.to_str().unwrap(), None);

        let before = Instant::now();
        let result = handle_pre_compact(input, &crate::host::ClaudeHost).await;
        let elapsed = before.elapsed();

        // Verify via a fresh handle before tearing down HOME.
        let storage = Storage::open_default().expect("storage must open in temp HOME");
        let session_exists = storage
            .get_session(session_id)
            .expect("get_session must not error")
            .is_some();
        let snapshots = storage
            .get_snapshots_by_session(session_id)
            .expect("get_snapshots_by_session must not error");

        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var("HOME");
        }
        let _ = std::fs::remove_dir_all(&temp_home);

        assert!(result.is_ok(), "handle_pre_compact must return Ok(())");
        assert!(
            elapsed < PRE_COMPACT_TIMEOUT,
            "handle_pre_compact must complete well within the {PRE_COMPACT_TIMEOUT:?} budget on the non-hanging path, took {elapsed:?}"
        );
        assert!(
            session_exists,
            "P1-5-precompact: session row must be ensured-or-created before the snapshot insert"
        );
        assert!(
            !snapshots.is_empty(),
            "P1-5-precompact REGRESSION: snapshot was lost to the sessions FK constraint"
        );
    }
}

//! `SessionEnd` hook handler - end session and create final snapshot.

use std::time::{Duration, Instant};

use anyhow::Result;
use clx_core::llm_health::{self as ollama_health, HealthStatus};
use clx_core::storage::Storage;
use clx_core::types::{Snapshot, SnapshotTrigger};
use tracing::{debug, info, warn};

use crate::embedding::{generate_and_store_embedding, truncate_to_char_boundary};
use crate::transcript::process_transcript;
use crate::types::HookInput;

/// Maximum time the `SessionEnd` handler may run before being cancelled.
/// Claude Code enforces a 1.5 s timeout on `SessionEnd` hooks; we use 1.0 s
/// to leave a 500 ms margin for process startup and I/O flush.
const SESSION_END_TIMEOUT: Duration = Duration::from_secs(1);

/// Maximum elapsed time before we skip embedding generation.
/// Embeddings are expensive; if we have already spent this much time on
/// database + transcript work we skip them to stay within budget.
const EMBEDDING_TIME_BUDGET: Duration = Duration::from_millis(500);

/// Handle `SessionEnd` hook - end session and create final snapshot.
///
/// Wraps the inner implementation in a tight timeout so the hook never
/// exceeds Claude Code's 1.5 s limit.
pub(crate) async fn handle_session_end(input: HookInput) -> Result<()> {
    if let Ok(result) =
        tokio::time::timeout(SESSION_END_TIMEOUT, handle_session_end_inner(input)).await
    {
        result
    } else {
        eprintln!(
            "SessionEnd: timed out after {}ms, skipping remaining work",
            SESSION_END_TIMEOUT.as_millis()
        );
        Ok(())
    }
}

/// Inner implementation that does the actual work.
async fn handle_session_end_inner(input: HookInput) -> Result<()> {
    let start = Instant::now();

    info!("SessionEnd: Ending session {}", input.session_id);

    // Check health cache *before* any Ollama operations.
    // If Ollama was recently unavailable (or unknown), skip all LLM work
    // to avoid the 2-4 s health-check timeout that causes "Hook cancelled".
    let health = ollama_health::read_cached_health();
    let ollama_available = matches!(health, HealthStatus::Available);
    if !ollama_available {
        debug!(
            "SessionEnd: Ollama health cache = {:?}, skipping LLM operations",
            health
        );
    }

    // Open storage
    let storage = match Storage::open_default() {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to open storage: {}", e);
            return Ok(());
        }
    };

    // Create final snapshot before ending
    let mut total_tokens: i64 = 0;
    if let Some(transcript_path) = &input.transcript_path {
        let result = process_transcript(transcript_path, ollama_available).await;
        total_tokens = result.input_tokens + result.output_tokens;

        let mut snapshot = Snapshot::new(input.session_id.clone(), SnapshotTrigger::Checkpoint);
        snapshot.summary = result.summary.clone();
        snapshot.key_facts = result.key_facts;
        snapshot.todos = result.todos;
        snapshot.message_count = result.message_count;
        snapshot.input_tokens = Some(result.input_tokens);
        snapshot.output_tokens = Some(result.output_tokens);

        match storage.create_snapshot(&snapshot) {
            Ok(snapshot_id) => {
                debug!(
                    "Created final snapshot {} for session {}",
                    snapshot_id, input.session_id
                );

                // Update session with final token counts
                if let Ok(Some(mut session)) = storage.get_session(input.session_id.as_str()) {
                    session.input_tokens = result.input_tokens;
                    session.output_tokens = result.output_tokens;
                    if let Err(e) = storage.update_session(&session) {
                        warn!("Failed to update session tokens: {}", e);
                    }
                }

                // Generate embedding for final snapshot — only if Ollama is
                // available AND we still have time budget remaining.
                if ollama_available && start.elapsed() < EMBEDDING_TIME_BUDGET {
                    if let Some(ref summary_text) = result.summary
                        && let Err(e) =
                            generate_and_store_embedding(snapshot_id, summary_text).await
                    {
                        warn!("Failed to store embedding: {}", e);
                    }
                } else if ollama_available {
                    debug!(
                        "SessionEnd: skipping embedding — elapsed {:?} exceeds budget {:?}",
                        start.elapsed(),
                        EMBEDDING_TIME_BUDGET
                    );
                }
            }
            Err(e) => {
                warn!("Failed to create final snapshot: {}", e);
            }
        }
    }

    // End the session
    if let Err(e) = storage.end_session(input.session_id.as_str()) {
        warn!("Failed to end session: {}", e);
    } else {
        debug!("Ended session {}", input.session_id);
    }

    eprintln!(
        "CLX: Session {} ended (~{} tokens)",
        truncate_to_char_boundary(input.session_id.as_str(), 8),
        total_tokens
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_constant_is_at_most_one_second() {
        assert!(SESSION_END_TIMEOUT <= Duration::from_secs(1));
    }

    #[test]
    fn embedding_budget_is_less_than_timeout() {
        assert!(EMBEDDING_TIME_BUDGET < SESSION_END_TIMEOUT);
    }

    /// Verify that `handle_session_end` completes within 1.5 s even when
    /// Ollama is unreachable (port 19999). This reproduces the original bug
    /// where the 2 s health-check timeout caused Claude Code to cancel the
    /// hook.
    #[tokio::test]
    async fn test_session_end_completes_within_timeout_with_unreachable_ollama() {
        use std::io::Write;

        // Isolated temp dirs so we don't touch real ~/.clx
        let temp_home =
            std::env::temp_dir().join(format!("clx-session-end-timeout-{}", std::process::id()));
        std::fs::create_dir_all(&temp_home).unwrap();

        // Write a small transcript file
        let transcript_path = temp_home.join("transcript.jsonl");
        {
            let mut f = std::fs::File::create(&transcript_path).unwrap();
            writeln!(f, r#"{{"type":"user","message":"hello"}}"#).unwrap();
            writeln!(f, r#"{{"type":"assistant","message":"hi"}}"#).unwrap();
        }

        // Point Ollama at an unreachable port and redirect HOME
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("CLX_OLLAMA_HOST", "http://127.0.0.1:19999");
            std::env::set_var("HOME", temp_home.to_str().unwrap());
        }

        let input = HookInput {
            session_id: "test-timeout-session".into(),
            transcript_path: Some(transcript_path.to_str().unwrap().to_string()),
            cwd: temp_home.to_str().unwrap().to_string(),
            hook_event_name: "SessionEnd".to_string(),
            tool_name: None,
            tool_use_id: None,
            tool_input: None,
            tool_response: None,
            source: None,
            trigger: None,
            prompt: None,
        };

        let before = Instant::now();
        let result = handle_session_end(input).await;
        let elapsed = before.elapsed();

        // Restore env vars
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var("CLX_OLLAMA_HOST");
            std::env::remove_var("HOME");
        }

        assert!(result.is_ok(), "handle_session_end must return Ok(())");
        assert!(
            elapsed < Duration::from_millis(1500),
            "SessionEnd must complete within 1.5s, took {elapsed:?}",
        );

        let _ = std::fs::remove_dir_all(&temp_home);
    }
}

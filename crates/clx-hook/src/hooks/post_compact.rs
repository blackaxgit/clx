//! `PostCompact` hook handler (Codex-only, P4).
//!
//! Codex fires `PostCompact` after a context compaction completes. CLX mirrors
//! the `PreCompact` token-count update for the *post*-compaction state: it
//! re-reads the (now compacted) transcript, recomputes the session token
//! counts, and persists them so downstream recall/stat surfaces reflect the
//! reduced context rather than the pre-compaction totals.
//!
//! Unlike `PreCompact` this handler does NOT create a snapshot: the
//! pre-compaction snapshot already captured the full conversation; a second
//! snapshot of the truncated post-compaction transcript would only dilute
//! recall quality. The job here is purely to keep the live session's token
//! accounting honest.
//!
//! Transcript backend selection goes through [`Host::transcript_backend`]:
//! - `Jsonl` (Claude / Codex): use the shared JSONL token counter.
//! - `Sqlite` (Cursor): no JSONL path; token update is skipped (degraded but
//!   not broken - Cursor does not emit `PostCompact` today, this arm is
//!   defensive).

use anyhow::Result;
use clx_core::storage::Storage;
use tracing::{debug, error, info, warn};

use crate::host::{Host, TranscriptBackend};
use crate::transcript::count_transcript_tokens;
use crate::types::HostNeutralInput;

/// Handle `PostCompact` - refresh session token counts for the compacted state.
pub(crate) async fn handle_post_compact(input: HostNeutralInput, host: &dyn Host) -> Result<()> {
    info!(
        "PostCompact: refreshing token counts for session {}",
        input.session_id
    );

    let storage = match Storage::open_default() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to open storage: {}", e);
            return Ok(());
        }
    };

    // Recompute token counts from the post-compaction transcript.
    let (input_tokens, output_tokens, message_count) = match host.transcript_backend() {
        TranscriptBackend::Jsonl => input
            .transcript_path
            .as_deref()
            .map_or((0, 0, 0), count_transcript_tokens),
        TranscriptBackend::Sqlite => {
            // Cursor stores transcripts in state.vscdb; no JSONL path. The
            // SQLite transcript reader is best-effort (P2) and Cursor does not
            // emit PostCompact, so the token update is intentionally skipped.
            debug!("PostCompact: SQLite transcript backend; skipping token refresh");
            (0, 0, 0)
        }
    };

    // Update the session row with the recomputed counts. Missing session is
    // non-fatal (a PostCompact can race a not-yet-recorded session).
    match storage.get_session(input.session_id.as_str()) {
        Ok(Some(mut session)) => {
            session.input_tokens = input_tokens;
            session.output_tokens = output_tokens;
            if let Err(e) = storage.update_session(&session) {
                warn!("Failed to update session tokens after compaction: {}", e);
            } else {
                debug!(
                    "PostCompact: updated session {} to ~{} tokens ({} messages)",
                    input.session_id,
                    input_tokens + output_tokens,
                    message_count
                );
            }
        }
        Ok(None) => {
            debug!(
                "PostCompact: session {} not found; nothing to update",
                input.session_id
            );
        }
        Err(e) => {
            warn!("Failed to load session for token refresh: {}", e);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{ClaudeHost, CursorHost};

    #[test]
    fn claude_backend_is_jsonl() {
        assert!(matches!(
            ClaudeHost.transcript_backend(),
            TranscriptBackend::Jsonl
        ));
    }

    #[test]
    fn cursor_backend_is_sqlite() {
        assert!(matches!(
            CursorHost.transcript_backend(),
            TranscriptBackend::Sqlite
        ));
    }

    /// A JSONL transcript with user+assistant turns yields a non-zero token
    /// count, which is what `PostCompact` persists. Uses the shared counter the
    /// handler calls for the Jsonl backend.
    #[test]
    fn jsonl_token_count_is_nonzero_for_real_turns() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("post-compact.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"{{"type":"user","message":{{"content":"hello world after compaction"}}}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"type":"assistant","message":{{"content":"compacted reply text"}}}}"#
        )
        .unwrap();
        drop(f);
        let (i, o, c) = count_transcript_tokens(path.to_str().unwrap());
        assert!(i > 0, "input tokens should be counted");
        assert!(o > 0, "output tokens should be counted");
        assert_eq!(c, 2, "two turns expected");
    }
}

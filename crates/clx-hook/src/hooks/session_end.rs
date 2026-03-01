//! `SessionEnd` hook handler - end session and create final snapshot.

use anyhow::Result;
use clx_core::storage::Storage;
use clx_core::types::{Snapshot, SnapshotTrigger};
use tracing::{debug, info, warn};

use crate::embedding::{generate_and_store_embedding, truncate_to_char_boundary};
use crate::transcript::process_transcript;
use crate::types::HookInput;

/// Handle `SessionEnd` hook - end session and create final snapshot
pub(crate) async fn handle_session_end(input: HookInput) -> Result<()> {
    info!("SessionEnd: Ending session {}", input.session_id);

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
        let result = process_transcript(transcript_path).await;
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

                // Generate embedding for final snapshot
                if let Some(ref summary_text) = result.summary
                    && let Err(e) = generate_and_store_embedding(snapshot_id, summary_text).await
                {
                    warn!("Failed to store embedding: {}", e);
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

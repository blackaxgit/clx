//! `PreCompact` hook handler - create snapshot before context compression.

use anyhow::Result;
use clx_core::storage::Storage;
use clx_core::types::{Snapshot, SnapshotTrigger};
use tracing::{debug, error, info, warn};

use crate::embedding::generate_and_store_embedding;
use crate::transcript::process_transcript;
use crate::types::{HookInput, TranscriptResult};

/// Handle `PreCompact` hook - create snapshot before context compression
pub(crate) async fn handle_pre_compact(input: HookInput) -> Result<()> {
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
        process_transcript(transcript_path).await
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

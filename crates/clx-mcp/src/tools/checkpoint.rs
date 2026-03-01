//! `clx_checkpoint` tool — Create a manual checkpoint/snapshot.

use serde_json::{Value, json};
use tracing::{debug, error, info, warn};

use clx_core::types::{SessionId, Snapshot, SnapshotTrigger};

use crate::protocol::types::INTERNAL_ERROR;
use crate::server::McpServer;
use crate::validation::{MAX_CONTENT_LEN, validate_optional_string_param};

impl McpServer {
    /// `clx_checkpoint` - Create a manual checkpoint
    pub(crate) fn tool_checkpoint(&self, args: &Value) -> Result<Value, (i32, String)> {
        let note = validate_optional_string_param(args, "note", MAX_CONTENT_LEN)?;

        debug!("Checkpoint with note: {:?}", note);

        let session_id = self
            .session_id
            .clone()
            .unwrap_or_else(|| SessionId::new("default"));

        let mut snapshot = Snapshot::new(session_id.clone(), SnapshotTrigger::Checkpoint);
        snapshot.summary.clone_from(&note);

        match self.storage.create_snapshot(&snapshot) {
            Ok(id) => {
                info!("Created checkpoint snapshot {}", id);

                // Generate and store embedding if a note was provided (non-blocking on failure)
                if let Some(ref note_text) = note {
                    let embedding_stored = self.store_embedding_for_snapshot(id, note_text);
                    if embedding_stored {
                        info!("Embedding stored for checkpoint snapshot {}", id);
                    } else {
                        warn!(
                            "Embedding not stored for checkpoint {} (continuing without embedding)",
                            id
                        );
                    }
                }

                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": format!("Checkpoint created (id: {}){}", id, note.as_deref().map(|n| format!(": {n}")).unwrap_or_default())
                    }]
                }))
            }
            Err(e) => {
                error!("Failed to create checkpoint: {}", e);
                Err((INTERNAL_ERROR, format!("Failed to create checkpoint: {e}")))
            }
        }
    }
}

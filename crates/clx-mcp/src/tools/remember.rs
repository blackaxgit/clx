//! `clx_remember` tool — Save information to the database with embeddings.

use serde_json::{Value, json};
use std::time::Duration;
use tracing::{debug, error, info, warn};

use clx_core::types::{SessionId, Snapshot, SnapshotTrigger};

use crate::protocol::types::INTERNAL_ERROR;
use crate::server::{EMBEDDING_STORE_TIMEOUT_MS, McpServer};
use crate::validation::{
    MAX_CONTENT_LEN, MAX_KEY_LEN, validate_optional_string_array, validate_string_param,
};

impl McpServer {
    /// `clx_remember` - Save information to the database
    pub(crate) fn tool_remember(&self, args: &Value) -> Result<Value, (i32, String)> {
        let text = validate_string_param(args, "text", MAX_CONTENT_LEN)?;
        let tags = validate_optional_string_array(args, "tags", 50, MAX_KEY_LEN)?;

        debug!("Remember text: {}, tags: {:?}", text, tags);

        let session_id = self
            .session_id
            .clone()
            .unwrap_or_else(|| SessionId::new("clx-standalone"));

        // Ensure the session exists (create if needed for standalone MCP usage)
        if self
            .storage
            .get_session(session_id.as_str())
            .ok()
            .flatten()
            .is_none()
        {
            let session = clx_core::types::Session::new(
                session_id.clone(),
                std::env::current_dir()
                    .map_or_else(|_| "/tmp".to_string(), |p| p.to_string_lossy().to_string()),
            );
            if let Err(e) = self.storage.create_session(&session) {
                warn!("Failed to create standalone session: {}", e);
            }
        }

        // Create a snapshot with the remembered information
        let mut snapshot = Snapshot::new(session_id.clone(), SnapshotTrigger::Manual);
        snapshot.summary = Some(format!(
            "Remembered: {}{}",
            text,
            if tags.is_empty() {
                String::new()
            } else {
                format!(" [tags: {}]", tags.join(", "))
            }
        ));
        snapshot.key_facts = Some(text.clone());

        match self.storage.create_snapshot(&snapshot) {
            Ok(id) => {
                info!("Created snapshot {} for remembered text", id);

                // Generate and store embedding asynchronously (non-blocking on failure)
                let embedding_stored = self.store_embedding_for_snapshot(id, &text);
                if embedding_stored {
                    info!("Embedding stored for snapshot {}", id);
                } else {
                    warn!(
                        "Embedding not stored for snapshot {} (continuing without embedding)",
                        id
                    );
                }

                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": format!("Successfully remembered information (snapshot id: {})", id)
                    }]
                }))
            }
            Err(e) => {
                error!("Failed to create snapshot: {}", e);
                Err((INTERNAL_ERROR, format!("Failed to save information: {e}")))
            }
        }
    }

    /// Generate and store embedding for a snapshot
    ///
    /// Returns true if embedding was successfully stored, false otherwise.
    /// This method never fails - it handles errors gracefully by logging and returning false.
    pub(crate) fn store_embedding_for_snapshot(&self, snapshot_id: i64, text: &str) -> bool {
        // Check if embedding infrastructure is available
        let (ollama, embedding_store) = match (&self.ollama_client, &self.embedding_store) {
            (Some(o), Some(e)) if e.is_vector_search_enabled() => (o, e),
            _ => {
                debug!("Embedding infrastructure not available, skipping embedding storage");
                return false;
            }
        };

        // Generate embedding with timeout
        let embedding_result = self.runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_millis(EMBEDDING_STORE_TIMEOUT_MS),
                ollama.embed(text, Some(&self.embed_model)),
            )
            .await
        });

        let embedding = match embedding_result {
            Ok(Ok(emb)) => {
                debug!(
                    "Generated embedding with {} dimensions for snapshot {}",
                    emb.len(),
                    snapshot_id
                );
                emb
            }
            Ok(Err(e)) => {
                warn!(
                    "Failed to generate embedding for snapshot {}: {}",
                    snapshot_id, e
                );
                return false;
            }
            Err(_) => {
                warn!(
                    "Embedding generation timed out after {}ms for snapshot {}",
                    EMBEDDING_STORE_TIMEOUT_MS, snapshot_id
                );
                return false;
            }
        };

        // Store embedding
        match embedding_store.store_embedding(snapshot_id, embedding) {
            Ok(()) => {
                debug!("Successfully stored embedding for snapshot {}", snapshot_id);
                true
            }
            Err(e) => {
                warn!(
                    "Failed to store embedding for snapshot {}: {}",
                    snapshot_id, e
                );
                false
            }
        }
    }
}

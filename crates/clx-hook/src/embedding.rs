//! Embedding generation and storage, plus path resolution utilities.

use anyhow::Result;
use clx_core::config::Config;
use clx_core::ollama::OllamaClient;
use clx_core::storage::Storage;
use tracing::{debug, info, warn};

/// Generate and store embedding for a snapshot
pub(crate) async fn generate_and_store_embedding(snapshot_id: i64, text: &str) -> Result<()> {
    let config = Config::load().unwrap_or_default();
    let ollama = match OllamaClient::new(config.ollama) {
        Ok(client) => client,
        Err(e) => {
            debug!(
                "Failed to create Ollama client for embedding: {}, skipping",
                e
            );
            return Ok(());
        }
    };

    if !ollama.is_available().await {
        debug!("Ollama not available, skipping embedding generation");
        return Ok(());
    }

    // Generate embedding with timeout
    let embedding =
        match tokio::time::timeout(std::time::Duration::from_secs(5), ollama.embed(text, None))
            .await
        {
            Ok(Ok(emb)) => emb,
            Ok(Err(e)) => {
                warn!("Failed to generate embedding: {}", e);
                return Ok(());
            }
            Err(_) => {
                warn!("Embedding generation timed out");
                return Ok(());
            }
        };

    debug!(
        "Generated embedding for snapshot {} ({} dimensions)",
        snapshot_id,
        embedding.len()
    );

    // Store embedding using the default database path
    let db_path = clx_core::paths::database_path();
    match Storage::create_embedding_store(&db_path) {
        Ok(emb_store) => {
            if emb_store.is_vector_search_enabled() {
                if let Err(e) = emb_store.store_embedding(snapshot_id, embedding) {
                    warn!("Failed to store embedding: {}", e);
                } else {
                    info!("Stored embedding for snapshot {}", snapshot_id);
                }
            } else {
                debug!("Vector search not enabled, skipping embedding storage");
            }
        }
        Err(e) => {
            warn!("Failed to create embedding store: {}", e);
        }
    }

    Ok(())
}

/// Resolve file paths in a command to their canonical forms (TOCTOU mitigation).
///
/// For commands that reference file paths, resolve symlinks before validation.
/// This is a best-effort mitigation -- full TOCTOU prevention requires Claude Code changes.
pub(crate) fn resolve_command_paths(command: &str) -> String {
    let parts: Vec<&str> = command.split_whitespace().collect();
    let mut resolved = Vec::new();
    let mut any_resolved = false;

    for part in &parts {
        if part.starts_with('/') || part.starts_with("./") || part.starts_with("../") {
            if let Ok(canonical) = std::fs::canonicalize(part) {
                let canonical_str = canonical.to_string_lossy().to_string();
                if canonical_str != *part {
                    debug!("TOCTOU: resolved path '{}' -> '{}'", part, canonical_str);
                    any_resolved = true;
                }
                resolved.push(canonical_str);
            } else {
                resolved.push(part.to_string());
            }
        } else {
            resolved.push(part.to_string());
        }
    }

    if any_resolved {
        debug!("TOCTOU: command paths resolved for validation");
    }

    resolved.join(" ")
}

/// Safely truncate a string to at most `max_bytes` bytes without splitting
/// a multi-byte UTF-8 character. Returns the longest prefix that fits.
pub(crate) fn truncate_to_char_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    // Find the largest char boundary <= max_bytes
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

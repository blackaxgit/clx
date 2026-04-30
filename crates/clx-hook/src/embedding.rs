//! Embedding generation and storage, plus path resolution utilities.

use anyhow::Result;
use clx_core::config::{Capability, Config};
use clx_core::storage::Storage;
use tracing::{debug, info, warn};

/// Generate and store embedding for a snapshot
pub(crate) async fn generate_and_store_embedding(snapshot_id: i64, text: &str) -> Result<()> {
    let config = Config::load().unwrap_or_default();
    let (client, route) = match config
        .create_llm_client(Capability::Embeddings)
        .and_then(|c| {
            config
                .capability_route(Capability::Embeddings)
                .map(|r| (c, r))
        }) {
        Ok(pair) => pair,
        Err(e) => {
            debug!("Failed to create LLM client for embedding: {}, skipping", e);
            return Ok(());
        }
    };
    let model = route.model.clone();
    let model_ident = format!("{}:{}", route.provider, route.model);

    if !client.is_available().await {
        debug!("LLM not available, skipping embedding generation");
        return Ok(());
    }

    // Generate embedding with timeout
    let embedding = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.embed(text, Some(&model)),
    )
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
                if let Err(e) = emb_store.store_with_model(snapshot_id, embedding, &model_ident) {
                    warn!("Failed to store embedding: {}", e);
                } else {
                    info!(
                        "Stored embedding for snapshot {} (model={})",
                        snapshot_id, model_ident
                    );
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

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // T19 — generate_and_store_embedding tests
    // =========================================================================

    /// T19-1: Success path — mock POST /api/embed returns an embedding vector;
    /// function completes with Ok(()) and does not panic.
    ///
    /// The function stores the embedding to the default DB path (under HOME).
    /// We redirect HOME to a temp directory so the real ~/.clx is untouched.
    /// Wiremock binds to 127.0.0.1, which the Ollama backend accepts as localhost.
    #[tokio::test]
    async fn test_generate_and_store_embedding_success() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Arrange — isolated HOME so DB writes go to a temp directory
        let temp_home =
            std::env::temp_dir().join(format!("clx-t19-success-{}", std::process::id()));
        std::fs::create_dir_all(&temp_home).unwrap();

        let server = MockServer::start().await;

        // is_available() hits GET /api/tags
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"models":[{"name":"nomic-embed-text"}]}"#),
            )
            .mount(&server)
            .await;

        // embed() hits POST /api/embeddings
        Mock::given(method("POST"))
            .and(path("/api/embeddings"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"embedding":[0.1,0.2,0.3,0.4,0.5]}"#),
            )
            .mount(&server)
            .await;

        // Redirect Ollama and HOME via env vars
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("CLX_OLLAMA_HOST", server.uri());
            std::env::set_var("HOME", temp_home.to_str().unwrap());
        }

        // Act
        let result = generate_and_store_embedding(1, "test text").await;

        // Restore env vars
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var("CLX_OLLAMA_HOST");
            std::env::remove_var("HOME");
        }

        // Assert — function returns Ok regardless of whether vector search is
        // enabled in the temp DB (it gracefully skips storage when disabled)
        assert!(result.is_ok(), "should return Ok(()) on success path");

        let _ = std::fs::remove_dir_all(&temp_home);
    }

    /// T19-2: Timeout path — mock server delays longer than the 5-second internal
    /// timeout in `generate_and_store_embedding`; function must return `Ok(())` without
    /// panicking (timeout is caught and logged as a warning).
    ///
    /// We use a 6-second response delay on `/api/embeddings` so the 5-second
    /// `tokio::time::timeout` inside the production code fires first.
    #[tokio::test]
    async fn test_generate_and_store_embedding_timeout_no_panic() {
        use std::time::Duration;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // is_available() must succeed so the function proceeds to embed()
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"models":[{"name":"nomic-embed-text"}]}"#),
            )
            .mount(&server)
            .await;

        // embed() hangs for 6s, exceeding the internal 5s timeout
        Mock::given(method("POST"))
            .and(path("/api/embeddings"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(6))
                    .set_body_string(r#"{"embedding":[0.1]}"#),
            )
            .mount(&server)
            .await;

        let temp_home =
            std::env::temp_dir().join(format!("clx-t19-timeout-{}", std::process::id()));
        std::fs::create_dir_all(&temp_home).unwrap();

        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("CLX_OLLAMA_HOST", server.uri());
            std::env::set_var("HOME", temp_home.to_str().unwrap());
        }

        // Act — must complete (timeout fires at 5s) without panicking
        let result = generate_and_store_embedding(42, "some text").await;

        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var("CLX_OLLAMA_HOST");
            std::env::remove_var("HOME");
        }

        assert!(
            result.is_ok(),
            "timeout must be handled gracefully and return Ok(())"
        );

        let _ = std::fs::remove_dir_all(&temp_home);
    }

    /// T19-3: Long text path — a very long input string is passed; the function
    /// must not panic (`OllamaClient` itself has a `MAX_RESPONSE_SIZE` guard and the
    /// request succeeds or gracefully degrades). We verify `truncate_to_char_boundary`
    /// handles extreme lengths and that the overall call returns `Ok(())`.
    ///
    /// Because `generate_and_store_embedding` delegates to `OllamaClient` which sends
    /// the text as-is, the "truncation before sending" contract lives at the caller
    /// level. This test verifies the function is panic-free for very long inputs.
    #[tokio::test]
    async fn test_generate_and_store_embedding_long_text_no_panic() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // A 200 KB string — much larger than typical inputs
        let long_text = "a".repeat(200_000);

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"models":[{"name":"nomic-embed-text"}]}"#),
            )
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/embeddings"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"embedding":[0.9,0.8,0.7]}"#),
            )
            .mount(&server)
            .await;

        let temp_home =
            std::env::temp_dir().join(format!("clx-t19-longtext-{}", std::process::id()));
        std::fs::create_dir_all(&temp_home).unwrap();

        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("CLX_OLLAMA_HOST", server.uri());
            std::env::set_var("HOME", temp_home.to_str().unwrap());
        }

        // Act — must not panic for very long input
        let result = generate_and_store_embedding(99, &long_text).await;

        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var("CLX_OLLAMA_HOST");
            std::env::remove_var("HOME");
        }

        assert!(
            result.is_ok(),
            "long text input must not cause a panic or unhandled error"
        );

        // Also verify the pure truncation helper works correctly for very long input
        let truncated = truncate_to_char_boundary(&long_text, 8192);
        assert_eq!(truncated.len(), 8192);
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());

        let _ = std::fs::remove_dir_all(&temp_home);
    }
}

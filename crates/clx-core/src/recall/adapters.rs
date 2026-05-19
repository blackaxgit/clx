//! Adapter implementations for the recall ports.
//!
//! Bridges Infrastructure types (`LlmClient`) to the Domain port
//! [`QueryEmbedder`]. The adapter is the *only* place inside the
//! `recall::` module tree that may import infra; everything else in
//! `recall::` speaks only ports.

use async_trait::async_trait;

use super::ports::QueryEmbedder;
use crate::llm::LlmClient;

/// Adapter that turns an `LlmClient` plus an optional bare model name
/// into a [`QueryEmbedder`]. The bare model is required for backends
/// without a baked-in default (Azure); Ollama tolerates `None`.
///
/// Holds borrowed references so the engine does not take ownership of
/// the LLM client (the hook process keeps the client for the full
/// lifetime of every recall).
pub struct LlmQueryEmbedder<'a> {
    client: &'a LlmClient,
    model: Option<&'a str>,
}

impl<'a> LlmQueryEmbedder<'a> {
    /// Build a new adapter. `model` is the bare deployment / model name
    /// (e.g. `"text-embedding-3-small"`), or `None` when the backend has a
    /// default.
    #[must_use]
    pub fn new(client: &'a LlmClient, model: Option<&'a str>) -> Self {
        Self { client, model }
    }
}

#[async_trait]
impl QueryEmbedder for LlmQueryEmbedder<'_> {
    async fn embed_query(&self, text: &str) -> crate::Result<Vec<f32>> {
        self.client
            .embed(text, self.model)
            .await
            .map_err(|e| crate::Error::InvalidInput(format!("embedding failed: {e}")))
    }
}

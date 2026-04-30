//! Provider-neutral LLM client surface and backend abstractions.

mod ollama;
mod azure;
mod retry;

pub use ollama::OllamaBackend;
pub use azure::AzureOpenAIBackend;
// pub use retry::with_backoff; — stub only, Task 3 adds the symbol

use std::time::Duration;
use thiserror::Error;

/// All operations the production code path performs against an LLM provider.
///
/// Only three methods because that's what `clx-hook`, `clx-mcp`, `clx-core::recall`,
/// and `clx-core::policy::llm` actually call. `list_models` from the legacy
/// Ollama client was unused outside tests and is intentionally not part of the
/// trait.
#[trait_variant::make(LlmBackend: Send)]
pub trait LocalLlmBackend {
    async fn generate(&self, prompt: &str, model: Option<&str>) -> Result<String, LlmError>;
    async fn embed(&self, text: &str, model: Option<&str>) -> Result<Vec<f32>, LlmError>;
    async fn is_available(&self) -> bool;
}

/// Provider-neutral error type. Concrete backends map their wire-level errors
/// into these variants.
#[derive(Debug, Error)]
pub enum LlmError {
    #[error("connection failed: {0}")]
    Connection(String),
    #[error("request timed out")]
    Timeout,
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("rate limited (retry_after: {retry_after:?})")]
    RateLimit { retry_after: Option<Duration> },
    #[error("deployment or model not found: {0}")]
    DeploymentNotFound(String),
    #[error("content filter triggered: {0}")]
    ContentFilter(String),
    #[error("server error {status}: {body}")]
    Server { status: u16, body: String },
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Static-dispatch wrapper that owns one of the concrete backend types and
/// forwards trait calls. Avoids `Box<dyn LlmBackend>` and the heap allocation
/// it forces on every async call.
pub enum LlmClient {
    Ollama(OllamaBackend),
    Azure(AzureOpenAIBackend),
}

impl LlmClient {
    pub async fn generate(&self, prompt: &str, model: Option<&str>) -> Result<String, LlmError> {
        match self {
            Self::Ollama(b) => b.generate(prompt, model).await,
            Self::Azure(b) => b.generate(prompt, model).await,
        }
    }

    pub async fn embed(&self, text: &str, model: Option<&str>) -> Result<Vec<f32>, LlmError> {
        match self {
            Self::Ollama(b) => b.embed(text, model).await,
            Self::Azure(b) => b.embed(text, model).await,
        }
    }

    pub async fn is_available(&self) -> bool {
        match self {
            Self::Ollama(b) => b.is_available().await,
            Self::Azure(b) => b.is_available().await,
        }
    }
}

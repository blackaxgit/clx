//! Provider-neutral LLM client surface and backend abstractions.

mod azure;
pub mod fallback;
mod ollama;
mod openai_wire;
mod openrouter;
pub mod retry;

pub use azure::AzureOpenAIBackend;
pub use fallback::FallbackClient;
pub use ollama::{OllamaBackend, OllamaError};
pub use openrouter::OpenRouterBackend;
pub use retry::{RetryConfig, with_backoff};

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

impl LlmError {
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            LlmError::Timeout | LlmError::Connection(_) | LlmError::RateLimit { .. }
        ) || matches!(
            self,
            LlmError::Server { status, .. } if (500..=599).contains(status) || *status == 408
        )
    }

    #[must_use]
    pub fn kind_str(&self) -> &'static str {
        match self {
            LlmError::Connection(_) => "connection",
            LlmError::Timeout => "timeout",
            LlmError::Auth(_) => "auth",
            LlmError::RateLimit { .. } => "rate_limit",
            LlmError::DeploymentNotFound(_) => "deployment_not_found",
            LlmError::ContentFilter(_) => "content_filter",
            LlmError::Server { .. } => "server",
            LlmError::InvalidResponse(_) => "invalid_response",
            LlmError::Serialization(_) => "serialization",
        }
    }
}

/// Static-dispatch wrapper that owns one of the concrete backend types and
/// forwards trait calls. Avoids `Box<dyn LlmBackend>` and the heap allocation
/// it forces on every async call.
pub enum LlmClient {
    Ollama(OllamaBackend),
    Azure(AzureOpenAIBackend),
    OpenRouter(OpenRouterBackend),
    Fallback(FallbackClient),
}

impl std::fmt::Debug for LlmClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ollama(_) => f.write_str("LlmClient::Ollama(..)"),
            Self::Azure(_) => f.write_str("LlmClient::Azure(..)"),
            Self::OpenRouter(_) => f.write_str("LlmClient::OpenRouter(..)"),
            Self::Fallback(_) => f.write_str("LlmClient::Fallback(..)"),
        }
    }
}

impl LlmClient {
    pub async fn generate(&self, prompt: &str, model: Option<&str>) -> Result<String, LlmError> {
        match self {
            Self::Ollama(b) => b.generate(prompt, model).await,
            Self::Azure(b) => b.generate(prompt, model).await,
            Self::OpenRouter(b) => b.generate(prompt, model).await,
            Self::Fallback(b) => b.generate(prompt, model).await,
        }
    }

    pub async fn embed(&self, text: &str, model: Option<&str>) -> Result<Vec<f32>, LlmError> {
        match self {
            Self::Ollama(b) => b.embed(text, model).await,
            Self::Azure(b) => b.embed(text, model).await,
            Self::OpenRouter(b) => b.embed(text, model).await,
            Self::Fallback(b) => b.embed(text, model).await,
        }
    }

    pub async fn is_available(&self) -> bool {
        match self {
            Self::Ollama(b) => b.is_available().await,
            Self::Azure(b) => b.is_available().await,
            Self::OpenRouter(b) => b.is_available().await,
            Self::Fallback(b) => b.is_available().await,
        }
    }
}

#[cfg(test)]
mod llm_client_openrouter_plumbing_tests {
    //! WP2 plumbing test (mandated by the WP2 task): constructs
    //! `LlmClient::OpenRouter` directly and exercises all three forwarding
    //! arms. WP3 is the work package that wires a config-driven constructor
    //! path (`build_client_for_provider`); until then, this test is what
    //! keeps the new variant from being dead code and proves the forwarding
    //! arms added above are correct.
    use super::*;
    use secrecy::SecretString;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

    fn client(backend: OpenRouterBackend) -> LlmClient {
        LlmClient::OpenRouter(backend)
    }

    #[tokio::test]
    async fn openrouter_variant_forwards_generate_embed_and_is_available() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "hello from openrouter" } }]
            })))
            .mount(&mock)
            .await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/api/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
            .mount(&mock)
            .await;

        let backend = OpenRouterBackend::new(
            &mock.uri(),
            5_000,
            RetryConfig {
                max_retries: 0,
                ..Default::default()
            },
            None,
            None,
            SecretString::new("test-key".to_string().into()),
        )
        .expect("loopback endpoint must construct OK");
        let llm = client(backend);

        // Debug impl forwarding arm.
        assert_eq!(format!("{llm:?}"), "LlmClient::OpenRouter(..)");

        // generate() forwarding arm.
        let out = llm
            .generate("hi", Some("anthropic/claude-3.5-sonnet"))
            .await;
        assert_eq!(out.unwrap(), "hello from openrouter");

        // embed() forwarding arm — chat-only backend, must error without a
        // network call (AC7); the mock above only registers chat/models
        // paths, so a stray embeddings call would surface as a 404 instead
        // of this specific InvalidResponse variant.
        let embed_err = llm.embed("text", Some("m")).await;
        assert!(matches!(embed_err, Err(LlmError::InvalidResponse(_))));

        // is_available() forwarding arm.
        assert!(llm.is_available().await);
    }
}

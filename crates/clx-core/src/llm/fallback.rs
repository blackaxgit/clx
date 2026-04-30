//! Primary→secondary LLM provider fallback wrapper.
//!
//! Wraps two `LlmClient` instances. On a transient error from the primary,
//! falls back to the secondary. After a fallback event, a 30-second
//! in-process cooldown skips the primary entirely so a sustained outage
//! does not pay the latency penalty of always hitting the dead primary first.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::llm::{LlmClient, LlmError, LocalLlmBackend};

/// Sticky-fallback duration after a primary failure.
const COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct FallbackClient {
    primary: Box<LlmClient>,
    fallback: Box<LlmClient>,
    /// If set, overrides the caller's `model` arg when delegating to the
    /// fallback. Necessary because providers don't share model names
    /// (e.g. `gpt-5.4-mini` only exists on Azure).
    fallback_model: Option<String>,
    /// `Some(t)` means primary failed at instant `t`; skip primary until
    /// `t.elapsed() >= COOLDOWN`.
    last_primary_failure: Mutex<Option<Instant>>,
}

impl FallbackClient {
    #[must_use]
    pub fn new(primary: LlmClient, fallback: LlmClient, fallback_model: Option<String>) -> Self {
        Self {
            primary: Box::new(primary),
            fallback: Box::new(fallback),
            fallback_model,
            last_primary_failure: Mutex::new(None),
        }
    }

    fn use_fallback_directly(&self) -> bool {
        match *self
            .last_primary_failure
            .lock()
            .expect("poisoned cooldown lock")
        {
            Some(t) => t.elapsed() < COOLDOWN,
            None => false,
        }
    }

    fn record_primary_failure(&self) {
        *self
            .last_primary_failure
            .lock()
            .expect("poisoned cooldown lock") = Some(Instant::now());
    }

    fn fb_model<'a>(&'a self, caller: Option<&'a str>) -> Option<&'a str> {
        self.fallback_model.as_deref().or(caller)
    }

    /// Test-only accessor — exposes whether cooldown is currently active.
    #[cfg(test)]
    pub(crate) fn cooldown_active(&self) -> bool {
        self.use_fallback_directly()
    }
}

impl LocalLlmBackend for FallbackClient {
    async fn generate(&self, prompt: &str, model: Option<&str>) -> Result<String, LlmError> {
        if self.use_fallback_directly() {
            let fb_model = self.fb_model(model).map(str::to_owned);
            return Box::pin(self.fallback.generate(prompt, fb_model.as_deref())).await;
        }
        match Box::pin(self.primary.generate(prompt, model)).await {
            Ok(v) => Ok(v),
            Err(e) if e.is_transient() => {
                tracing::warn!(
                    op = "generate",
                    error.kind = %e.kind_str(),
                    "primary failed; falling back"
                );
                self.record_primary_failure();
                let fb_model = self.fb_model(model).map(str::to_owned);
                Box::pin(self.fallback.generate(prompt, fb_model.as_deref())).await
            }
            Err(e) => Err(e),
        }
    }

    async fn embed(&self, text: &str, model: Option<&str>) -> Result<Vec<f32>, LlmError> {
        if self.use_fallback_directly() {
            let fb_model = self.fb_model(model).map(str::to_owned);
            return Box::pin(self.fallback.embed(text, fb_model.as_deref())).await;
        }
        match Box::pin(self.primary.embed(text, model)).await {
            Ok(v) => Ok(v),
            Err(e) if e.is_transient() => {
                tracing::warn!(
                    op = "embed",
                    error.kind = %e.kind_str(),
                    "primary failed; falling back"
                );
                self.record_primary_failure();
                let fb_model = self.fb_model(model).map(str::to_owned);
                Box::pin(self.fallback.embed(text, fb_model.as_deref())).await
            }
            Err(e) => Err(e),
        }
    }

    async fn is_available(&self) -> bool {
        // Either backend healthy means "fallback path is alive."
        Box::pin(self.primary.is_available()).await || Box::pin(self.fallback.is_available()).await
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use crate::config::AzureOpenAIConfig;
    use crate::llm::AzureOpenAIBackend;
    use crate::llm::retry::RetryConfig;
    use secrecy::SecretString;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

    fn cfg(endpoint: String) -> AzureOpenAIConfig {
        AzureOpenAIConfig {
            endpoint,
            api_key_env: None,
            api_key_file: None,
            api_version: None,
            timeout_ms: 5_000,
            retry: RetryConfig {
                max_retries: 0,
                ..Default::default()
            },
        }
    }

    fn allow_local() {
        // SAFETY: test-only env var manipulation
        unsafe {
            std::env::set_var("CLX_ALLOW_AZURE_HOSTS", "127.0.0.1,localhost");
        }
    }

    fn azure(uri: String) -> LlmClient {
        let backend =
            AzureOpenAIBackend::new(&cfg(uri), SecretString::new("k".to_string().into())).unwrap();
        LlmClient::Azure(backend)
    }

    #[tokio::test]
    async fn fallback_on_primary_503_succeeds() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(503).set_body_string("overloaded"))
            .expect(1)
            .mount(&primary_mock)
            .await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "from fallback" } }]
            })))
            .expect(1)
            .mount(&fallback_mock)
            .await;

        let fc = FallbackClient::new(
            azure(primary_mock.uri()),
            azure(fallback_mock.uri()),
            Some("fallback-model".into()),
        );

        let out = fc.generate("hi", Some("primary-model")).await.unwrap();
        assert_eq!(out, "from fallback");
    }

    #[tokio::test]
    async fn fallback_not_used_on_terminal_error() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .expect(1)
            .mount(&primary_mock)
            .await;

        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("should not fire"))
            .expect(0)
            .mount(&fallback_mock)
            .await;

        let fc = FallbackClient::new(azure(primary_mock.uri()), azure(fallback_mock.uri()), None);

        let r = fc.generate("hi", Some("m")).await;
        assert!(matches!(r, Err(LlmError::Auth(_))));
    }

    #[tokio::test]
    async fn cooldown_skips_primary_after_failure() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&primary_mock)
            .await;

        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "ok" } }]
            })))
            .expect(2)
            .mount(&fallback_mock)
            .await;

        let fc = FallbackClient::new(azure(primary_mock.uri()), azure(fallback_mock.uri()), None);

        let _ = fc.generate("hi", Some("m")).await.unwrap();
        assert!(fc.cooldown_active());

        let out = fc.generate("hi again", Some("m")).await.unwrap();
        assert_eq!(out, "ok");
    }
}

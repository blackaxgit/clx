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
    use serial_test::serial;
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
    #[serial(env_azure_hosts_fallback)]
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
    #[serial(env_azure_hosts_fallback)]
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
    #[serial(env_azure_hosts_fallback)]
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

    // Branch: embed() primary transient failure -> fallback succeeds.
    // Mirrors the generate() path but exercises the separate embed arm.
    // Kills a mutant that drops the embed fallback (would surface the 503)
    // or that forwards to the primary a second time.
    #[tokio::test]
    #[serial(env_azure_hosts_fallback)]
    async fn embed_falls_back_on_primary_transient() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/embeddings"))
            .respond_with(ResponseTemplate::new(503).set_body_string("overloaded"))
            .expect(1)
            .mount(&primary_mock)
            .await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/embeddings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{ "embedding": vec![0.25f32; 8] }]
            })))
            .expect(1)
            .mount(&fallback_mock)
            .await;

        let fc = FallbackClient::new(
            azure(primary_mock.uri()),
            azure(fallback_mock.uri()),
            Some("fb-embed-model".into()),
        );

        let v = fc
            .embed("hi", Some("primary-embed-model"))
            .await
            .expect("embed should fall back to secondary");
        assert_eq!(v.len(), 8);
        assert!(fc.cooldown_active(), "embed failure must arm the cooldown");
    }

    // Branch: embed() primary terminal (401) error -> NO fallback, error surfaces.
    // Kills a mutant that treats every embed error as transient and falls back.
    #[tokio::test]
    #[serial(env_azure_hosts_fallback)]
    async fn embed_terminal_error_does_not_fall_back() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/embeddings"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .expect(1)
            .mount(&primary_mock)
            .await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/embeddings"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&fallback_mock)
            .await;

        let fc = FallbackClient::new(azure(primary_mock.uri()), azure(fallback_mock.uri()), None);

        let r = fc.embed("hi", Some("m")).await;
        assert!(matches!(r, Err(LlmError::Auth(_))));
        assert!(
            !fc.cooldown_active(),
            "a terminal error must NOT arm the fallback cooldown"
        );
    }

    // Branch: fb_model() returns the caller's model when fallback_model is None.
    // We prove this by mounting the fallback to only succeed for the caller's
    // model arg. Kills a mutant that hard-codes the fallback model to None or
    // drops the `.or(caller)` fallback in `fb_model`.
    #[tokio::test]
    #[serial(env_azure_hosts_fallback)]
    async fn fallback_uses_caller_model_when_no_override() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&primary_mock)
            .await;

        // Fallback only matches when the request carries the caller's model.
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .and(matchers::body_partial_json(serde_json::json!({
                "model": "caller-model"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "via-caller-model" } }]
            })))
            .expect(1)
            .mount(&fallback_mock)
            .await;

        // fallback_model = None -> fb_model must reuse the caller's model arg.
        let fc = FallbackClient::new(azure(primary_mock.uri()), azure(fallback_mock.uri()), None);

        let out = fc.generate("hi", Some("caller-model")).await.unwrap();
        assert_eq!(out, "via-caller-model");
    }

    // Branch: is_available() short-circuits true when the PRIMARY is healthy.
    // Kills a mutant that flips the `||` to `&&` (would require both up) or one
    // that always returns false.
    #[tokio::test]
    #[serial(env_azure_hosts_fallback)]
    async fn is_available_true_when_primary_healthy() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/openai/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .mount(&primary_mock)
            .await;
        // Fallback would 500 if consulted; primary's 200 must short-circuit.
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/openai/v1/models"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&fallback_mock)
            .await;

        let fc = FallbackClient::new(azure(primary_mock.uri()), azure(fallback_mock.uri()), None);
        assert!(fc.is_available().await, "primary healthy => available");
    }

    // Branch: is_available() falls through to the FALLBACK when primary is down.
    // Kills a mutant that only checks the primary (would return false here).
    #[tokio::test]
    #[serial(env_azure_hosts_fallback)]
    async fn is_available_true_when_only_fallback_healthy() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/openai/v1/models"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&primary_mock)
            .await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/openai/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .mount(&fallback_mock)
            .await;

        let fc = FallbackClient::new(azure(primary_mock.uri()), azure(fallback_mock.uri()), None);
        assert!(
            fc.is_available().await,
            "primary down but fallback healthy => still available"
        );
    }

    // Branch: is_available() returns false only when BOTH backends are down.
    // Kills a mutant that returns true unconditionally.
    #[tokio::test]
    #[serial(env_azure_hosts_fallback)]
    async fn is_available_false_when_both_down() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/openai/v1/models"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&primary_mock)
            .await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/openai/v1/models"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&fallback_mock)
            .await;

        let fc = FallbackClient::new(azure(primary_mock.uri()), azure(fallback_mock.uri()), None);
        assert!(
            !fc.is_available().await,
            "both backends down => not available"
        );
    }
}
